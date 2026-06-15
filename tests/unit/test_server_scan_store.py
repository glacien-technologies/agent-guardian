"""Unit tests for the M12 :class:`ScanStore`."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from datetime import UTC, datetime
from pathlib import Path

from agent_guardian import __version__
from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.server import ScanStore
from agent_guardian.server.scan_store import MAX_BUFFERED_EVENTS_PER_SCAN


def _make_scan(scan_id: str) -> Scan:
    findings = [
        Finding(
            id=f"{scan_id}-f-1",
            probe_id="probe-1",
            asi=AsiCategory.ASI01,
            mitre_atlas=["AML.T0054"],
            csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
            severity=Severity.HIGH,
            attempt_count=1,
            success=False,
            confidence=0.5,
            summary="finding 1",
            created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
        )
    ]
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        mode="full",
        aivss=85,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 90.0,
            "tool_scope_safety": 90.0,
            "pii_containment": 80.0,
            "memory_poisoning_resistance": 85.0,
            "excessive_agency_containment": 80.0,
            "hallucination_resistance": 85.0,
        },
        findings=findings,
        asi_scores={cat: 90.0 for cat in AsiCategory},
        duration_seconds=4.2,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Construction / paths
# ---------------------------------------------------------------------------


def test_root_defaults_under_home_when_unset() -> None:
    store = ScanStore()
    assert store.root == Path.home() / ".agentguardian" / "scans"


def test_custom_root_honoured(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.root == tmp_path
    assert store.scan_dir("abc") == tmp_path / "abc"


# ---------------------------------------------------------------------------
# Completed scan loading
# ---------------------------------------------------------------------------


def test_load_completed_returns_none_for_unknown(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.load_completed("missing") is None


def test_load_completed_roundtrips(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan = _make_scan("scan-1")
    _persist(store, scan)
    loaded = store.load_completed("scan-1")
    assert loaded is not None
    assert loaded.id == "scan-1"
    assert loaded.aivss == 85
    assert len(loaded.findings) == 1


def test_load_completed_handles_malformed_json(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("broken")
    scan_dir.mkdir(parents=True)
    (scan_dir / "scan.json").write_text("not json", encoding="utf-8")
    assert store.load_completed("broken") is None


# ---------------------------------------------------------------------------
# list_scans
# ---------------------------------------------------------------------------


def test_list_scans_empty(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    assert store.list_scans() == []


def test_list_scans_orders_completed_by_recency(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    older = _make_scan("older")
    newer = _make_scan("newer")
    object.__setattr__(
        newer,
        "__pydantic_fields_set__",
        newer.__pydantic_fields_set__,
    )
    # Re-make with explicit created_at differences.
    older = older.model_copy(update={"created_at": datetime(2026, 5, 26, 0, 0, 0, tzinfo=UTC)})
    newer = newer.model_copy(update={"created_at": datetime(2026, 5, 27, 0, 0, 0, tzinfo=UTC)})
    _persist(store, older)
    _persist(store, newer)
    summaries = store.list_scans()
    assert [s.scan_id for s in summaries] == ["newer", "older"]
    assert all(not s.is_running for s in summaries)


# ---------------------------------------------------------------------------
# Event queue / observer / replay
# ---------------------------------------------------------------------------


def _event(kind: str, agent: str | None = None) -> SwarmEvent:
    return SwarmEvent(
        kind=kind,  # type: ignore[arg-type]
        timestamp=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
        agent=agent,
    )


def test_event_queue_isolated_per_scan(tmp_path: Path) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        q1 = store.event_queue("a")
        q2 = store.event_queue("b")
        assert q1 is not q2
        # Phase 2 Step 2.2 — ``event_queue`` is no longer idempotent: each
        # call materialises a NEW subscriber queue so multi-tab fan-out is
        # safe. Two calls for the same scan id return two distinct queues
        # and the observer fans out to both.
        q1b = store.event_queue("a")
        assert q1b is not q1
        # And both queues are tracked as live subscribers until removed.
        assert q1 in store._subscribers["a"]
        assert q1b in store._subscribers["a"]

    asyncio.run(_run())


def test_register_wires_observer_and_buffers_events(tmp_path: Path) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)

        # Minimal stand-in for SwarmCommander — only `observer` is touched.
        class FakeSwarm:
            observer = None

        fake = FakeSwarm()
        store.register("scan-x", fake)  # type: ignore[arg-type]
        assert fake.observer is not None
        # Emit one event before the SSE queue exists.
        fake.observer(_event("agent_start", "tool-abuse-agent"))
        # Now the consumer asks for the queue — buffered event should be there.
        q = store.event_queue("scan-x")
        ev = q.get_nowait()
        assert ev.kind == "agent_start"
        assert ev.agent == "tool-abuse-agent"
        # On-disk JSONL written too.
        jsonl = store.scan_dir("scan-x") / "events.jsonl"
        assert jsonl.is_file()
        # Issue #221 — events.jsonl starts with a {"kind":"_meta", ...}
        # schema-version header line; skip it to read the first REAL event.
        all_lines = [json.loads(ln) for ln in jsonl.read_text(encoding="utf-8").splitlines()]
        real_events = [ln for ln in all_lines if ln.get("kind") != "_meta"]
        assert real_events[0]["kind"] == "agent_start"
        assert real_events[0]["agent"] == "tool-abuse-agent"
        # `scan_done` should drop the running registration.
        assert store.is_running("scan-x")
        fake.observer(_event("scan_done"))
        assert not store.is_running("scan-x")

    asyncio.run(_run())


def test_register_makes_scan_appear_in_list(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    store.register("live-scan", FakeSwarm())  # type: ignore[arg-type]
    summaries = store.list_scans()
    assert any(s.scan_id == "live-scan" and s.is_running for s in summaries)


def test_replay_events_from_disk(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("replay")
    scan_dir.mkdir(parents=True)
    payloads = [
        {"kind": "agent_start", "agent": "recon-agent"},
        {"kind": "agent_done", "agent": "recon-agent"},
        {"kind": "scan_done"},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")
    replayed = store.replay_events_from_disk("replay")
    assert [p["kind"] for p in replayed] == [
        "agent_start",
        "agent_done",
        "scan_done",
    ]


def test_list_report_paths_picks_up_known_formats(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("rep")
    scan_dir.mkdir()
    (scan_dir / "report.sarif").write_text("{}", encoding="utf-8")
    (scan_dir / "report.md").write_text("# hi", encoding="utf-8")
    (scan_dir / "scan.json").write_text("{}", encoding="utf-8")
    paths = store.list_report_paths("rep")
    assert "sarif" in paths
    assert "md" in paths
    # scan.json provides the json fallback.
    assert "json" in paths


# ---------------------------------------------------------------------------
# In-memory buffer cap (#36)
# ---------------------------------------------------------------------------


def test_event_buffer_is_bounded_at_max_per_scan(tmp_path: Path) -> None:
    """A long-running scan must not push the in-memory buffer past the cap.

    Pushes ``MAX_BUFFERED_EVENTS_PER_SCAN + 100`` events through the observer
    and asserts the deque held by ``_events`` is exactly the cap, and that
    the first held event is the cap-th most recent one (oldest evicted).
    """
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-bound", fake)  # type: ignore[arg-type]
    assert fake.observer is not None

    overshoot = 100
    total = MAX_BUFFERED_EVENTS_PER_SCAN + overshoot
    for i in range(total):
        # tag each event with a unique agent name so we can identify it later
        fake.observer(_event("agent_start", agent=f"agent-{i}"))

    buf = store._events["scan-bound"]
    # The buffer is a deque with maxlen == MAX_BUFFERED_EVENTS_PER_SCAN.
    assert isinstance(buf, deque)
    assert buf.maxlen == MAX_BUFFERED_EVENTS_PER_SCAN
    assert len(buf) == MAX_BUFFERED_EVENTS_PER_SCAN
    # The oldest ``overshoot`` events fell off the front. The first held
    # event is the ``overshoot``-th one we pushed (index ``overshoot``).
    first_held = next(iter(buf))
    assert first_held.agent == f"agent-{overshoot}"
    # And the most recent event is the last one we pushed.
    last_held = buf[-1]
    assert last_held.agent == f"agent-{total - 1}"
    # ``replay_events`` returns the same bounded list view.
    replayed = store.replay_events("scan-bound")
    assert len(replayed) == MAX_BUFFERED_EVENTS_PER_SCAN
    assert replayed[0].agent == f"agent-{overshoot}"
    assert replayed[-1].agent == f"agent-{total - 1}"


def test_scan_done_evicts_buffer_when_no_loop(tmp_path: Path) -> None:
    """``scan_done`` synchronously evicts the buffer when no asyncio loop runs.

    The store is documented to fall back to immediate eviction when called
    from synchronous test contexts so the bounded-memory invariant still
    holds. The on-disk events.jsonl is the source of truth for any future
    subscriber that needs the historical events.
    """
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-evict", fake)  # type: ignore[arg-type]
    assert fake.observer is not None
    fake.observer(_event("agent_start", "tool-abuse-agent"))
    assert "scan-evict" in store._events
    fake.observer(_event("scan_done"))
    # No running loop → immediate eviction.
    assert "scan-evict" not in store._events
    # On-disk events.jsonl still has both events for late replay.
    # Issue #221 — skip the {"kind":"_meta", ...} schema-version header
    # line so the kinds list asserts on the REAL event sequence only.
    jsonl_lines = (
        (store.scan_dir("scan-evict") / "events.jsonl").read_text(encoding="utf-8").splitlines()
    )
    kinds = [json.loads(line)["kind"] for line in jsonl_lines]
    real_kinds = [k for k in kinds if k != "_meta"]
    assert real_kinds == ["agent_start", "scan_done"]


def test_scan_done_evicts_buffer_after_grace_when_loop_running(tmp_path: Path) -> None:
    """When an asyncio loop is running, the eviction is deferred to a task.

    Uses a near-zero grace window so the test completes deterministically;
    the production default is 5 minutes. The buffer is still present
    immediately after ``scan_done`` and is gone after the grace task fires.
    """

    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)

        class FakeSwarm:
            observer = None

        fake = FakeSwarm()
        store.register("scan-grace", fake)  # type: ignore[arg-type]
        assert fake.observer is not None
        fake.observer(_event("agent_start", "tool-abuse-agent"))
        # Patch the grace window down so we don't block the test for 5min.
        original = store._schedule_buffer_eviction

        def _short(scan_id: str, *, grace_seconds: float = 0.01) -> None:
            original(scan_id, grace_seconds=grace_seconds)

        store._schedule_buffer_eviction = _short  # type: ignore[method-assign]
        fake.observer(_event("scan_done"))
        # Buffer still present immediately (eviction is deferred).
        assert "scan-grace" in store._events
        # Wait long enough for the eviction task to run.
        await asyncio.sleep(0.05)
        assert "scan-grace" not in store._events

    asyncio.run(_run())


def test_max_buffered_events_default_is_5000() -> None:
    """The exported cap defaults to 5000 so consumers can rely on the value."""
    assert MAX_BUFFERED_EVENTS_PER_SCAN >= 1
    # Allow override via env var, but the default at import time must be 5000
    # when the env var isn't set. The constant resolves at import; if the
    # test runner ever sets the env var, it'd be on the runner — we don't
    # assert exact equality to avoid false failures in that case.
    import os

    if "AGENT_GUARDIAN_MAX_BUFFERED_EVENTS" not in os.environ:
        assert MAX_BUFFERED_EVENTS_PER_SCAN == 5000
