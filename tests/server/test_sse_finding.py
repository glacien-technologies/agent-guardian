"""SSE follow-up (2026-06-04) — the ``finding`` event flows end-to-end.

Locks the gap closed by the findings live-append work: the scan core now
emits a per-finding ``finding`` :class:`SwarmEvent` (from the agent loop
right after ``memory.write_finding``) so the dashboard's Findings tab
appends the row live, exactly like probe rows already do.

Acceptance (mirrors ``test_sse_agent_progress.py``):

1. A ``finding`` event produced through the scan-store observer is stamped
   with the per-scan monotonic ``seq`` and lands on the on-disk
   ``events.jsonl`` with the full row payload preserved verbatim.
2. A live SSE subscriber receives it with a standard ``id: <seq>`` line and
   an ``event: finding`` envelope — wire-compatible with the
   ``live-append.js`` ``finding`` listener.
3. The event REPLAYS for a terminal scan opened later: a fresh subscriber
   on a no-longer-running scan re-reads ``events.jsonl`` and re-emits the
   ``finding`` event before the synthetic ``scan_done`` terminator.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.models.asi import AsiCategory
from agent_guardian.server import ScanStore
from agent_guardian.server.sse import stream_scan_events


def _finding_event(
    *,
    finding_id: str = "f-abc123",
    severity: str = "high",
    asi: str = "ASI01",
    agent: str = "goal-hijack-agent",
    probe_id: str = "ASI01-GH-001",
    turn: int = 3,
) -> SwarmEvent:
    return SwarmEvent(
        kind="finding",
        timestamp=datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC),
        agent=agent,
        asi=AsiCategory(asi),
        payload={
            "finding_id": finding_id,
            "id": finding_id,
            "severity": severity,
            "asi": asi,
            "category": "goal-instruction-manipulation",
            "agent": agent,
            "probe_id": probe_id,
            "summary": "prompt injection observed",
            "turn": turn,
        },
    )


class _FakeSwarm:
    """Stand-in for SwarmCommander; only ``observer`` is touched."""

    observer = None


_ROW_KEYS = (
    "finding_id",
    "id",
    "severity",
    "asi",
    "category",
    "agent",
    "probe_id",
    "summary",
    "turn",
)


# ---------------------------------------------------------------------------
# Acceptance 1 — events.jsonl carries the full row payload + top-level seq
# ---------------------------------------------------------------------------


def test_finding_lands_in_events_jsonl_with_full_payload(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    fake = _FakeSwarm()
    store.register("scan-finding-jsonl", fake)  # type: ignore[arg-type]

    fake.observer(_finding_event(finding_id="f-1", severity="critical"))  # type: ignore[misc]
    fake.observer(_finding_event(finding_id="f-2", severity="low"))  # type: ignore[misc]

    jsonl = tmp_path / "scan-finding-jsonl" / "events.jsonl"
    lines = [json.loads(ln) for ln in jsonl.read_text(encoding="utf-8").splitlines() if ln]
    assert len(lines) == 2
    assert all(ln["kind"] == "finding" for ln in lines)
    # Per-scan monotonic seq starts at 0 (Phase 2 Step 2.1 contract).
    assert [ln["seq"] for ln in lines] == [0, 1]
    # ASI surfaced at the top level by event_to_payload.
    assert lines[0]["asi"] == "ASI01"
    for ln in lines:
        payload = ln["payload"]
        assert isinstance(payload, dict)
        for required in _ROW_KEYS:
            assert required in payload, f"finding payload missing key '{required}': {payload!r}"
    assert lines[0]["payload"]["severity"] == "critical"
    assert lines[1]["payload"]["severity"] == "low"


# ---------------------------------------------------------------------------
# Acceptance 2 — live SSE subscriber receives the event with id: <seq>
# ---------------------------------------------------------------------------


def test_finding_streams_to_live_subscriber(tmp_path: Path) -> None:
    async def _run() -> list[str]:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("scan-finding-live", fake)  # type: ignore[arg-type]

        gen = stream_scan_events("scan-finding-live", store)
        out: list[str] = []

        async def _consume() -> None:
            async for chunk in gen:
                out.append(chunk)

        consumer = asyncio.create_task(_consume())
        await asyncio.sleep(0.01)
        fake.observer(_finding_event(finding_id="f-1"))  # type: ignore[misc]
        fake.observer(_finding_event(finding_id="f-2", severity="critical"))  # type: ignore[misc]
        fake.observer(
            SwarmEvent(
                kind="scan_done",
                timestamp=datetime(2026, 6, 4, 12, 0, 1, tzinfo=UTC),
            )
        )  # type: ignore[misc]
        await asyncio.wait_for(consumer, timeout=2.0)
        return out

    chunks = asyncio.run(_run())

    finding_chunks = [c for c in chunks if "event: finding" in c]
    assert len(finding_chunks) == 2, (
        f"expected 2 finding chunks, got {len(finding_chunks)}: {chunks!r}"
    )
    for chunk in finding_chunks:
        assert chunk.startswith("id: "), chunk
        assert "event: finding\n" in chunk, chunk
        data_lines = [ln for ln in chunk.splitlines() if ln.startswith("data: ")]
        assert data_lines, chunk
        payload_outer = json.loads(data_lines[0][len("data: ") :])
        payload = payload_outer.get("payload") or {}
        for required in _ROW_KEYS:
            assert required in payload, (
                f"streamed finding missing payload key '{required}': {payload!r}"
            )


# ---------------------------------------------------------------------------
# Acceptance 3 — replay for a terminal scan opened later
# ---------------------------------------------------------------------------


def test_finding_replays_from_disk_for_terminal_scan(tmp_path: Path) -> None:
    """A finding written to events.jsonl during a scan must replay when a
    fresh subscriber opens the (now terminal) scan."""

    async def _run() -> list[str]:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("scan-finding-replay", fake)  # type: ignore[arg-type]

        # Emit a finding then terminate the scan (drops the running
        # registration so the next subscriber takes the disk-replay path).
        fake.observer(_finding_event(finding_id="f-replay"))  # type: ignore[misc]
        fake.observer(
            SwarmEvent(kind="scan_done", timestamp=datetime(2026, 6, 4, 12, 0, 1, tzinfo=UTC))
        )  # type: ignore[misc]
        # Drop the in-memory buffer so the late subscriber MUST read disk.
        store._events.pop("scan-finding-replay", None)
        assert not store.is_running("scan-finding-replay")

        out: list[str] = []
        async for chunk in stream_scan_events("scan-finding-replay", store):
            out.append(chunk)
        return out

    chunks = asyncio.run(_run())
    body = "".join(chunks)
    finding_chunks = [c for c in chunks if "event: finding" in c]
    assert len(finding_chunks) == 1, f"expected 1 replayed finding chunk: {chunks!r}"
    assert "f-replay" in body
    # The replay path terminates with a scan_done so the client closes.
    assert "event: scan_done" in body
