"""Phase 2 Step 2.1 -- per-scan monotonic ``seq`` persistence + SSE id-line.

Locks the four-part acceptance criterion from designs/sse-flow-and-live-ui.md
"Phase 2 decisions (resolved 2026-06-03)" item 2:

1. The first event of a scan gets ``seq=0`` and subsequent events increment.
2. Every line of ``events.jsonl`` carries ``seq`` as a top-level field (NOT
   nested inside payload), so a cross-process replay can filter by it.
3. :func:`format_sse_event` emits a standard SSE ``id: <seq>`` line per the
   W3C EventSource spec when ``seq`` is present.
4. A client reconnecting with ``Last-Event-ID: 5`` on a 10-event scan
   receives only events 6..9 (and the synthetic ``scan_done`` terminator).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.sse import format_sse_event, stream_scan_events


def _event(kind: str, agent: str | None = "tool-abuse-agent") -> SwarmEvent:
    return SwarmEvent(
        kind=kind,  # type: ignore[arg-type]
        timestamp=datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC),
        agent=agent,
    )


# ---------------------------------------------------------------------------
# Acceptance 1 -- per-scan monotonic counter
# ---------------------------------------------------------------------------


def test_observer_stamps_seq_starting_at_zero(tmp_path: Path) -> None:
    """The observer stamps ``seq=0`` on the first event and increments."""
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-seq", fake)  # type: ignore[arg-type]

    fake.observer(_event("agent_start"))
    fake.observer(_event("agent_progress"))
    fake.observer(_event("agent_done"))

    buffered = store.replay_events(scan_id="scan-seq")
    assert [e.seq for e in buffered] == [0, 1, 2]


def test_observer_seq_is_per_scan_not_global(tmp_path: Path) -> None:
    """Two concurrent scans each get an independent counter starting at 0."""
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake_a = FakeSwarm()
    fake_b = FakeSwarm()
    store.register("scan-A", fake_a)  # type: ignore[arg-type]
    store.register("scan-B", fake_b)  # type: ignore[arg-type]

    fake_a.observer(_event("agent_start"))
    fake_b.observer(_event("agent_start"))
    fake_a.observer(_event("agent_done"))
    fake_b.observer(_event("agent_done"))

    a_seqs = [e.seq for e in store.replay_events(scan_id="scan-A")]
    b_seqs = [e.seq for e in store.replay_events(scan_id="scan-B")]
    assert a_seqs == [0, 1]
    assert b_seqs == [0, 1]


# ---------------------------------------------------------------------------
# Acceptance 2 -- top-level ``seq`` in events.jsonl
# ---------------------------------------------------------------------------


def test_events_jsonl_carries_seq_as_top_level_field(tmp_path: Path) -> None:
    """Each on-disk JSONL line has ``seq`` at the top level, NOT in payload."""
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-jsonl", fake)  # type: ignore[arg-type]

    fake.observer(_event("agent_start"))
    fake.observer(_event("agent_done"))

    jsonl = tmp_path / "scan-jsonl" / "events.jsonl"
    lines = [json.loads(ln) for ln in jsonl.read_text(encoding="utf-8").splitlines() if ln]
    assert len(lines) == 2
    assert lines[0]["seq"] == 0
    assert lines[1]["seq"] == 1
    # seq must NOT be nested inside payload -- a cross-process replay must
    # be able to filter by prefix without descending into the payload tree.
    assert "seq" not in lines[0].get("payload", {})
    assert "seq" not in lines[1].get("payload", {})


# ---------------------------------------------------------------------------
# Acceptance 3 -- ``id:`` line in the SSE wire format
# ---------------------------------------------------------------------------


def test_format_sse_event_emits_id_line_when_seq_is_set() -> None:
    """A SwarmEvent with ``seq`` is rendered with a leading ``id: <seq>``."""
    rendered = format_sse_event("agent_start", {"kind": "agent_start", "seq": 7})
    # The id line MUST precede the event line per the W3C EventSource spec.
    assert rendered.startswith("id: 7\nevent: agent_start\n")
    assert rendered.endswith("\n\n")


def test_format_sse_event_omits_id_line_when_seq_absent() -> None:
    """Legacy / unsequenced events keep the pre-Phase-2 wire format."""
    rendered = format_sse_event("checkpoint", {"score": 91})
    assert not rendered.startswith("id:")
    assert rendered.startswith("event: checkpoint\n")


def test_format_sse_event_explicit_seq_argument_wins() -> None:
    """Caller-supplied ``seq`` parameter overrides any value in the payload."""
    rendered = format_sse_event(
        "agent_done",
        {"kind": "agent_done", "seq": 3},
        seq=42,
    )
    assert rendered.startswith("id: 42\n")


# ---------------------------------------------------------------------------
# Acceptance 4 -- Last-Event-ID header skips earlier events
# ---------------------------------------------------------------------------


def test_stream_with_last_event_id_skips_disk_replay_up_to_cursor(tmp_path: Path) -> None:
    """A reconnect with ``Last-Event-ID: 5`` on a 10-event scan yields 6..9."""
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("scan-resume")
    scan_dir.mkdir()
    payloads = []
    for i in range(10):
        kind = "scan_done" if i == 9 else "agent_progress"
        payloads.append({"kind": kind, "seq": i, "payload": {"i": i}})
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")

    async def _collect(last: str | int | None) -> list[str]:
        out: list[str] = []
        async for chunk in stream_scan_events("scan-resume", store, last_event_id=last):
            out.append(chunk)
        return out

    chunks = asyncio.run(_collect(5))
    seen_ids = [int(c.split("\n", 1)[0][len("id: ") :]) for c in chunks if c.startswith("id: ")]
    # Events 0..5 must NOT be re-emitted; 6..9 (incl. the seq=9 scan_done) must.
    assert all(s > 5 for s in seen_ids), seen_ids
    assert 6 in seen_ids and 9 in seen_ids


def test_stream_without_last_event_id_emits_all_disk_events(tmp_path: Path) -> None:
    """No header => full replay from seq=0. Locks the no-filter baseline."""
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("scan-no-resume")
    scan_dir.mkdir()
    payloads = [
        {"kind": "agent_progress", "seq": 0, "payload": {}},
        {"kind": "agent_progress", "seq": 1, "payload": {}},
        {"kind": "scan_done", "seq": 2, "payload": {}},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")

    async def _collect() -> list[str]:
        out: list[str] = []
        async for chunk in stream_scan_events("scan-no-resume", store):
            out.append(chunk)
        return out

    chunks = asyncio.run(_collect())
    seen_ids = [int(c.split("\n", 1)[0][len("id: ") :]) for c in chunks if c.startswith("id: ")]
    assert seen_ids == [0, 1, 2]


def test_stream_with_non_numeric_last_event_id_replays_from_start(tmp_path: Path) -> None:
    """A malformed ``Last-Event-ID`` from a stale build is treated as absent."""
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("scan-bad-id")
    scan_dir.mkdir()
    payloads = [
        {"kind": "agent_progress", "seq": 0, "payload": {}},
        {"kind": "scan_done", "seq": 1, "payload": {}},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")

    async def _collect() -> list[str]:
        out: list[str] = []
        async for chunk in stream_scan_events("scan-bad-id", store, last_event_id="not-a-number"):
            out.append(chunk)
        return out

    chunks = asyncio.run(_collect())
    seen_ids = [int(c.split("\n", 1)[0][len("id: ") :]) for c in chunks if c.startswith("id: ")]
    assert seen_ids == [0, 1]


def test_stream_live_queue_filters_by_last_event_id(tmp_path: Path) -> None:
    """Live queue drain also respects ``Last-Event-ID`` to avoid duplicates."""
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-live-resume", fake)  # type: ignore[arg-type]

    async def _run() -> list[str]:
        out: list[str] = []
        # Pre-emit 3 events BEFORE the consumer subscribes -- these will
        # be replayed onto the queue at subscription time. Reconnect at
        # ``Last-Event-ID: 1`` should skip seqs 0 and 1.
        fake.observer(_event("agent_start"))
        fake.observer(_event("agent_progress"))
        fake.observer(_event("agent_progress"))
        gen = stream_scan_events("scan-live-resume", store, last_event_id=1)

        async def consume() -> None:
            async for chunk in gen:
                out.append(chunk)

        consumer = asyncio.create_task(consume())
        await asyncio.sleep(0.01)
        fake.observer(_event("scan_done"))
        await asyncio.wait_for(consumer, timeout=2.0)
        return out

    chunks = asyncio.run(_run())
    seen_ids = [int(c.split("\n", 1)[0][len("id: ") :]) for c in chunks if c.startswith("id: ")]
    # seqs 0 and 1 are filtered; 2 (the third agent_progress) and 3
    # (scan_done) come through.
    assert 0 not in seen_ids
    assert 1 not in seen_ids
    assert 2 in seen_ids
    assert 3 in seen_ids


# ---------------------------------------------------------------------------
# Route-level wiring: the HTTP header flows through to the stream filter.
# ---------------------------------------------------------------------------


def test_events_endpoint_honours_last_event_id_header(tmp_path: Path) -> None:
    """The ``/scan/{id}/events`` route reads ``Last-Event-ID`` and filters."""
    store = ScanStore(root_dir=tmp_path)
    scan_dir = store.scan_dir("scan-header")
    scan_dir.mkdir()
    payloads = [
        {"kind": "agent_start", "seq": 0, "payload": {}},
        {"kind": "agent_progress", "seq": 1, "payload": {}},
        {"kind": "agent_done", "seq": 2, "payload": {}},
        {"kind": "scan_done", "seq": 3, "payload": {}},
    ]
    with (scan_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for p in payloads:
            fh.write(json.dumps(p) + "\n")

    client = TestClient(create_app(scan_store=store))
    with client.stream(
        "GET",
        "/scan/scan-header/events",
        headers={"Last-Event-ID": "1"},
    ) as resp:
        assert resp.status_code == 200
        body = b"".join(resp.iter_bytes()).decode("utf-8")
    # Pre-cursor events must not appear; post-cursor events must.
    assert "id: 0\n" not in body
    assert "id: 1\n" not in body
    assert "id: 2\n" in body
    assert "id: 3\n" in body
