"""SSE Phase 2 Step 2.3 — ``agent_progress`` flows end-to-end.

Locks the acceptance criterion from designs/sse-flow-and-live-ui.md
"Phase 2 decisions (resolved 2026-06-03)" item 3:

1. An ``agent_progress`` :class:`SwarmEvent` produced by the agent loop
   is stamped with the per-scan ``seq`` by the scan-store observer.
2. It lands on the on-disk ``events.jsonl`` with the four required
   payload fields (``agent_name``, ``turn``, ``max_turns``, ``probe_id``)
   preserved verbatim.
3. It is fanned out to live SSE subscribers with a standard ``id: <seq>``
   line and an ``event: agent_progress`` envelope — wire-compatible with
   the ``phase-spine.js`` consumer registered for the same kind.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.server import ScanStore
from agent_guardian.server.sse import stream_scan_events


def _progress_event(
    *,
    agent_name: str = "tool-abuse-agent",
    turn: int = 1,
    max_turns: int = 3,
    probe_id: str | None = "TA-001",
) -> SwarmEvent:
    return SwarmEvent(
        kind="agent_progress",
        timestamp=datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC),
        agent=agent_name,
        payload={
            "agent_name": agent_name,
            "turn": turn,
            "max_turns": max_turns,
            "probe_id": probe_id,
        },
    )


class _FakeSwarm:
    """Stand-in for SwarmCommander; only ``observer`` is touched."""

    observer = None


# ---------------------------------------------------------------------------
# Acceptance 1 — events.jsonl carries the four-field payload + top-level seq
# ---------------------------------------------------------------------------


def test_agent_progress_lands_in_events_jsonl_with_full_payload(tmp_path: Path) -> None:
    """The observer writes the event to disk with the four required
    payload fields and a top-level monotonic ``seq``."""
    store = ScanStore(root_dir=tmp_path)
    fake = _FakeSwarm()
    store.register("scan-progress-jsonl", fake)  # type: ignore[arg-type]

    fake.observer(_progress_event(turn=1, probe_id=None))  # type: ignore[misc]
    fake.observer(_progress_event(turn=2, probe_id="TA-001"))  # type: ignore[misc]
    fake.observer(_progress_event(turn=3, probe_id="TA-007"))  # type: ignore[misc]

    jsonl = tmp_path / "scan-progress-jsonl" / "events.jsonl"
    lines = [json.loads(ln) for ln in jsonl.read_text(encoding="utf-8").splitlines() if ln]
    assert len(lines) == 3
    assert all(ln["kind"] == "agent_progress" for ln in lines)
    # Per-scan monotonic seq starts at 0 (Phase 2 Step 2.1 contract).
    assert [ln["seq"] for ln in lines] == [0, 1, 2]
    # The four required payload fields survive the round-trip.
    for idx, ln in enumerate(lines):
        payload = ln["payload"]
        assert isinstance(payload, dict)
        for required in ("agent_name", "turn", "max_turns", "probe_id"):
            assert required in payload, (
                f"agent_progress[{idx}] missing payload key '{required}': {payload!r}"
            )
        assert payload["turn"] == idx + 1
        assert payload["max_turns"] == 3
        assert payload["agent_name"] == "tool-abuse-agent"
    # First event has probe_id=None (the very first turn has no prior seed).
    assert lines[0]["payload"]["probe_id"] is None
    assert lines[1]["payload"]["probe_id"] == "TA-001"
    assert lines[2]["payload"]["probe_id"] == "TA-007"


# ---------------------------------------------------------------------------
# Acceptance 2 — live SSE subscriber receives the event with id: <seq>
# ---------------------------------------------------------------------------


def test_agent_progress_streams_to_live_subscriber(tmp_path: Path) -> None:
    """A live SSE subscriber sees the ``agent_progress`` event with a
    standard ``id: <seq>`` line and an ``event: agent_progress`` envelope."""

    async def _run() -> list[str]:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("scan-progress-live", fake)  # type: ignore[arg-type]

        gen = stream_scan_events("scan-progress-live", store)
        out: list[str] = []

        async def _consume() -> None:
            async for chunk in gen:
                out.append(chunk)

        consumer = asyncio.create_task(_consume())
        await asyncio.sleep(0.01)
        # Emit through the observer so the multiplexer fans out to the
        # live consumer queue.
        fake.observer(_progress_event(turn=1, probe_id=None))  # type: ignore[misc]
        fake.observer(_progress_event(turn=2, probe_id="TA-001"))  # type: ignore[misc]
        fake.observer(
            SwarmEvent(
                kind="scan_done",
                timestamp=datetime(2026, 6, 3, 12, 0, 1, tzinfo=UTC),
            )
        )  # type: ignore[misc]
        await asyncio.wait_for(consumer, timeout=2.0)
        return out

    chunks = asyncio.run(_run())

    progress_chunks = [c for c in chunks if "event: agent_progress" in c]
    assert len(progress_chunks) == 2, (
        f"expected 2 agent_progress chunks, got {len(progress_chunks)}: {chunks!r}"
    )

    # Each chunk carries the SSE id line per Step 2.1.
    for chunk in progress_chunks:
        assert chunk.startswith("id: "), chunk
        assert "event: agent_progress\n" in chunk, chunk
        # The data line is JSON with the four required payload fields.
        data_lines = [ln for ln in chunk.splitlines() if ln.startswith("data: ")]
        assert data_lines, chunk
        payload_outer = json.loads(data_lines[0][len("data: ") :])
        payload = payload_outer.get("payload") or {}
        for required in ("agent_name", "turn", "max_turns", "probe_id"):
            assert required in payload, (
                f"streamed agent_progress missing payload key '{required}': {payload!r}"
            )
