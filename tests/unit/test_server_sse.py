"""SSE plumbing tests for the M12 dashboard."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.sse import format_sse_event, stream_scan_events


def _event(kind: str, agent: str | None = "tool-abuse-agent") -> SwarmEvent:
    return SwarmEvent(
        kind=kind,  # type: ignore[arg-type]
        timestamp=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
        agent=agent,
    )


# ---------------------------------------------------------------------------
# Wire-format unit tests
# ---------------------------------------------------------------------------


def test_format_sse_event_shape() -> None:
    rendered = format_sse_event("checkpoint", {"score": 91, "band": "EXCELLENT"})
    assert rendered.endswith("\n\n")
    lines = rendered.strip().split("\n")
    assert lines[0] == "event: checkpoint"
    assert lines[1].startswith("data: ")
    payload = json.loads(lines[1][len("data: ") :])
    assert payload == {"score": 91, "band": "EXCELLENT"}


def test_format_sse_event_minimal_payload() -> None:
    rendered = format_sse_event("scan_done", {})
    assert "event: scan_done" in rendered
    assert "data: {}" in rendered


# ---------------------------------------------------------------------------
# Replay tests
# ---------------------------------------------------------------------------


def test_stream_replay_from_disk_emits_terminator(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("scan-disk")
    scan_dir.mkdir()
    payloads = [
        {"kind": "agent_start", "agent": "recon"},
        {"kind": "agent_done", "agent": "recon"},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")

    async def _collect() -> list[str]:
        out: list[str] = []
        async for chunk in stream_scan_events("scan-disk", store):
            out.append(chunk)
        return out

    chunks = asyncio.run(_collect())
    kinds = [c.split("\n", 1)[0] for c in chunks]
    assert "event: agent_start" in kinds
    assert "event: agent_done" in kinds
    # Even without scan_done on disk, the stream should synthesise one.
    assert "event: scan_done" in kinds


def test_stream_replay_with_explicit_scan_done(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("scan-disk-2")
    scan_dir.mkdir()
    payloads = [
        {"kind": "agent_start", "agent": "recon"},
        {"kind": "scan_done"},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")

    async def _collect() -> list[str]:
        out: list[str] = []
        async for chunk in stream_scan_events("scan-disk-2", store):
            out.append(chunk)
        return out

    chunks = asyncio.run(_collect())
    # Exactly one scan_done event (no synthetic terminator on top).
    done_count = sum(1 for c in chunks if c.startswith("event: scan_done"))
    assert done_count == 1


# ---------------------------------------------------------------------------
# Live stream tests
# ---------------------------------------------------------------------------


def test_stream_live_terminates_on_scan_done(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-live", fake)  # type: ignore[arg-type]

    async def _run() -> list[str]:
        out: list[str] = []
        gen = stream_scan_events("scan-live", store)

        async def consume() -> None:
            async for chunk in gen:
                out.append(chunk)

        consumer = asyncio.create_task(consume())
        # Emit a sequence of events.
        await asyncio.sleep(0)
        fake.observer(_event("agent_start"))
        await asyncio.sleep(0.01)
        fake.observer(_event("finding"))
        await asyncio.sleep(0.01)
        fake.observer(_event("scan_done"))
        await asyncio.wait_for(consumer, timeout=2.0)
        return out

    chunks = asyncio.run(_run())
    # Phase 2 Step 2.1 — observer stamps seq so each live chunk is now
    # prefixed with ``id: <seq>\n``. Match the event line anywhere in
    # the chunk rather than only at byte 0.
    assert any("event: agent_start" in c for c in chunks)
    assert any("event: finding" in c for c in chunks)
    assert any("event: scan_done" in c for c in chunks)


# ---------------------------------------------------------------------------
# Heartbeat / keepalive — SSE Phase 1, Step 5
# ---------------------------------------------------------------------------


def test_stream_emits_data_heartbeat_on_quiet_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The freshness-dot client relies on ``event: heartbeat`` (NOT ``:``
    comment) because EventSource ``onmessage`` does not fire on comment-only
    lines. Verifies a quiet scan emits the typed heartbeat event."""
    from agent_guardian.server import sse as sse_mod

    monkeypatch.setattr(sse_mod, "_HEARTBEAT_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(sse_mod, "_QUEUE_POLL_INTERVAL_SECONDS", 0.001)
    monkeypatch.setattr(sse_mod, "_KEEPALIVE_INTERVAL_SECONDS", 0.001)

    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-heartbeat", fake)  # type: ignore[arg-type]

    async def _run() -> list[str]:
        out: list[str] = []
        gen = stream_scan_events("scan-heartbeat", store)

        async def consume() -> None:
            async for chunk in gen:
                out.append(chunk)
                if any(c.startswith("event: heartbeat") for c in out):
                    fake.observer(_event("scan_done"))

        consumer = asyncio.create_task(consume())
        await asyncio.wait_for(consumer, timeout=3.0)
        return out

    chunks = asyncio.run(_run())
    heartbeats = [c for c in chunks if c.startswith("event: heartbeat")]
    assert heartbeats, "expected at least one ``event: heartbeat`` on quiet stream"
    # Payload must carry a numeric ``now`` for client clock-sync use.
    data_line = heartbeats[0].split("\n")[1]
    assert data_line.startswith("data: ")
    payload = json.loads(data_line[len("data: ") :])
    assert isinstance(payload.get("now"), (int, float))


# ---------------------------------------------------------------------------
# Route-level test via TestClient
# ---------------------------------------------------------------------------


def test_events_endpoint_404_for_unknown_scan(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    client = TestClient(create_app(scan_store=store))
    resp = client.get("/scan/missing/events")
    assert resp.status_code == 404


def test_events_endpoint_replays_completed_scan(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("scan-route")
    scan_dir.mkdir()
    payloads = [
        {"kind": "agent_start", "agent": "drift"},
        {"kind": "scan_done"},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")

    client = TestClient(create_app(scan_store=store))
    with client.stream("GET", "/scan/scan-route/events") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        body = b"".join(resp.iter_bytes()).decode("utf-8")
    assert "event: agent_start" in body
    assert "event: scan_done" in body
