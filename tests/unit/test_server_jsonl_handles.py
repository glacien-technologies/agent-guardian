"""Tests for the per-scan persistent events.jsonl writer + LRU cap + close-all.

The launch-readiness audit flagged the legacy ``open/close per event`` path
as a measurable bottleneck for chatty scans. This module asserts the new
behaviour: one cached writer per active scan, capped at
``MAX_OPEN_JSONL_HANDLES``, flushed-and-closed on shutdown.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.scan_store import MAX_OPEN_JSONL_HANDLES


def _event(kind: str, agent: str | None = None) -> SwarmEvent:
    return SwarmEvent(
        kind=kind,  # type: ignore[arg-type]
        timestamp=datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC),
        agent=agent,
    )


def test_jsonl_writer_cached_after_first_event(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-cache", fake)  # type: ignore[arg-type]
    assert fake.observer is not None
    fake.observer(_event("agent_start", "a"))
    # The writer is now in the LRU cache.
    assert "scan-cache" in store._jsonl_files
    fh_first = store._jsonl_files["scan-cache"]
    fake.observer(_event("agent_progress", "a"))
    # The same handle is reused (no re-open).
    fh_second = store._jsonl_files["scan-cache"]
    assert fh_first is fh_second


def test_jsonl_writer_flushed_so_concurrent_reader_sees_bytes(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-flush", fake)  # type: ignore[arg-type]
    assert fake.observer is not None
    fake.observer(_event("agent_start", "a"))
    # We did NOT call scan_done — the writer is still open. A reader must
    # already see the bytes we wrote because the observer flushes after
    # each event. Without the flush, the buffer would still hold the line.
    jsonl = tmp_path / "scan-flush" / "events.jsonl"
    text = jsonl.read_text(encoding="utf-8")
    assert text.strip() != ""
    # Issue #221 — events.jsonl now writes a {"kind":"_meta",
    # "schema_version": "events-v1", ...} header as the first line of
    # every fresh file. Skip it to assert on the first REAL event.
    lines = [json.loads(line) for line in text.splitlines()]
    real_events = [ln for ln in lines if ln.get("kind") != "_meta"]
    assert real_events, "expected at least one non-meta event"
    assert real_events[0]["kind"] == "agent_start"


def test_jsonl_writer_closed_on_scan_done(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-close", fake)  # type: ignore[arg-type]
    assert fake.observer is not None
    fake.observer(_event("agent_start", "a"))
    assert "scan-close" in store._jsonl_files
    fake.observer(_event("scan_done"))
    # Writer removed after scan_done.
    assert "scan-close" not in store._jsonl_files


def test_jsonl_writer_lru_caps_at_max_open_handles(tmp_path: Path) -> None:
    """Registering more scans than the cap evicts the LRU handle."""
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    # We need MAX_OPEN_JSONL_HANDLES + 5 active scans, each emitting one
    # event so the writer is materialised in the cache.
    handles_needed = MAX_OPEN_JSONL_HANDLES + 5
    fakes = []
    for i in range(handles_needed):
        fake = FakeSwarm()
        store.register(f"scan-{i:04d}", fake)  # type: ignore[arg-type]
        fakes.append(fake)
        assert fake.observer is not None
        fake.observer(_event("agent_start", f"a-{i}"))
    # Cache should be capped at MAX_OPEN_JSONL_HANDLES; the first 5 scans
    # were evicted (LRU).
    assert len(store._jsonl_files) == MAX_OPEN_JSONL_HANDLES
    # The oldest scans were evicted.
    assert "scan-0000" not in store._jsonl_files
    assert "scan-0004" not in store._jsonl_files
    # The newest scans are still cached.
    assert f"scan-{handles_needed - 1:04d}" in store._jsonl_files
    # Crucially: ALL of the events were still written to disk, because
    # the evicted writer flushed + closed before being dropped.
    for i in range(handles_needed):
        jsonl = tmp_path / f"scan-{i:04d}" / "events.jsonl"
        assert jsonl.is_file(), f"scan-{i:04d} missing events.jsonl"
        # One line written.
        assert jsonl.read_text(encoding="utf-8").strip()


def test_close_all_flushes_and_closes(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake_a = FakeSwarm()
    fake_b = FakeSwarm()
    store.register("scan-a", fake_a)  # type: ignore[arg-type]
    store.register("scan-b", fake_b)  # type: ignore[arg-type]
    assert fake_a.observer is not None
    assert fake_b.observer is not None
    fake_a.observer(_event("agent_start", "a"))
    fake_b.observer(_event("agent_start", "b"))
    assert len(store._jsonl_files) == 2
    store.close_all()
    assert len(store._jsonl_files) == 0
    # On-disk events still present.
    for sid in ("scan-a", "scan-b"):
        text = (tmp_path / sid / "events.jsonl").read_text(encoding="utf-8")
        assert text.strip()


def test_app_lifespan_closes_handles_on_shutdown(tmp_path: Path) -> None:
    """The FastAPI lifespan tear-down calls close_all on the store."""
    store = ScanStore(root_dir=tmp_path)
    app = create_app(scan_store=store)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-life", fake)  # type: ignore[arg-type]
    assert fake.observer is not None
    fake.observer(_event("agent_start", "a"))
    assert "scan-life" in store._jsonl_files

    # Running the TestClient in a context manager triggers the lifespan
    # exit, which should drain the cache.
    with TestClient(app) as client:
        client.get("/healthz")
    assert len(store._jsonl_files) == 0
