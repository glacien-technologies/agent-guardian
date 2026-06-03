"""Phase 2 Step 2.2 -- per-subscriber queue multiplexer.

Locks the multi-tab multicast acceptance criterion from
designs/sse-flow-and-live-ui.md "Phase 2 decisions (resolved 2026-06-03)"
item 1:

1. Two simulated SSE consumers attached to the same ``scan_id``
   independently each receive every event emitted through the observer.
2. Per-subscriber backpressure: a slow consumer whose queue is full
   drops events for ITSELF; a fast consumer on the same scan continues
   to receive the complete stream.
3. ``remove_subscriber`` on stream close detaches the queue from the
   store so the observer fan-out doesn't leak a queue forever.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.server import ScanStore


def _event(kind: str, agent: str | None = "tool-abuse-agent") -> SwarmEvent:
    return SwarmEvent(
        kind=kind,  # type: ignore[arg-type]
        timestamp=datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC),
        agent=agent,
    )


class _FakeSwarm:
    """Stand-in for SwarmCommander -- only ``observer`` is touched."""

    observer = None


# ---------------------------------------------------------------------------
# Acceptance 1 -- two simulated tabs each receive all events
# ---------------------------------------------------------------------------


def test_two_subscribers_each_receive_all_events(tmp_path: Path) -> None:
    """Two consumers on the same scan_id each independently see all events."""

    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("scan-mtab", fake)  # type: ignore[arg-type]

        # Two simulated SSE consumers attach BEFORE any event is emitted.
        # Per Step 2.2 semantics each call returns a brand new queue.
        q_tab_a: asyncio.Queue[SwarmEvent] = store.event_queue("scan-mtab")
        q_tab_b: asyncio.Queue[SwarmEvent] = store.event_queue("scan-mtab")

        assert q_tab_a is not q_tab_b, "each subscriber must get its own queue"
        assert q_tab_a in store._subscribers["scan-mtab"]
        assert q_tab_b in store._subscribers["scan-mtab"]

        # Emit 10 events through the observer; observer must fan out to
        # BOTH queues.
        for i in range(10):
            fake.observer(_event("agent_progress" if i < 9 else "scan_done"))  # type: ignore[misc]

        # Drain each consumer independently. Each must see all 10 events
        # with monotonic seq 0..9.
        a_seen = []
        b_seen = []
        while not q_tab_a.empty():
            a_seen.append(q_tab_a.get_nowait())
        while not q_tab_b.empty():
            b_seen.append(q_tab_b.get_nowait())

        assert [e.seq for e in a_seen] == list(range(10)), (
            f"tab A missed events: seqs={[e.seq for e in a_seen]}"
        )
        assert [e.seq for e in b_seen] == list(range(10)), (
            f"tab B missed events: seqs={[e.seq for e in b_seen]}"
        )

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Acceptance 2 -- per-subscriber backpressure (slow consumer doesn't starve
# the fast one)
# ---------------------------------------------------------------------------


def test_slow_consumer_drops_fast_consumer_unaffected(tmp_path: Path) -> None:
    """A full slow-consumer queue drops for itself; the fast consumer is fine.

    Locks the per-subscriber backpressure contract: when one
    subscriber's :class:`asyncio.Queue` is full the observer drops the
    event for THAT subscriber only and continues fanning out to the
    rest. Without this isolation a stalled browser tab would gum up
    every other listener on the same scan.
    """

    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("scan-bp", fake)  # type: ignore[arg-type]

        # Subscriber A: tiny cap so it goes full after a single put.
        slow: asyncio.Queue[SwarmEvent] = asyncio.Queue(maxsize=1)
        store._subscribers.setdefault("scan-bp", []).append(slow)
        # Subscriber B: unbounded — represents a healthy tab keeping up.
        fast: asyncio.Queue[SwarmEvent] = asyncio.Queue()
        store._subscribers["scan-bp"].append(fast)

        # Emit 5 events. Slow tab's first put succeeds; the remaining 4
        # raise QueueFull and the observer drops for slow only. Fast
        # must receive ALL 5.
        for _ in range(5):
            fake.observer(_event("agent_progress"))  # type: ignore[misc]

        slow_count = 0
        while not slow.empty():
            slow.get_nowait()
            slow_count += 1
        fast_count = 0
        while not fast.empty():
            fast.get_nowait()
            fast_count += 1

        assert slow_count == 1, f"slow consumer should hold only its cap (1); got {slow_count}"
        assert fast_count == 5, (
            f"fast consumer must be unaffected by slow's backpressure; got {fast_count}"
        )

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Acceptance 3 -- explicit cleanup via remove_subscriber prevents leak
# ---------------------------------------------------------------------------


def test_remove_subscriber_detaches_from_fanout(tmp_path: Path) -> None:
    """After ``remove_subscriber`` the observer no longer feeds the queue."""

    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        fake = _FakeSwarm()
        store.register("scan-rm", fake)  # type: ignore[arg-type]

        q_a = store.event_queue("scan-rm")
        q_b = store.event_queue("scan-rm")

        # Detach tab A.
        store.remove_subscriber("scan-rm", q_a)
        assert q_a not in store._subscribers.get("scan-rm", [])
        assert q_b in store._subscribers["scan-rm"]

        # New event after removal: must reach B, must NOT reach A.
        a_size_before = q_a.qsize()
        fake.observer(_event("agent_progress"))  # type: ignore[misc]
        assert q_a.qsize() == a_size_before, (
            "removed subscriber must not receive post-removal events"
        )
        assert q_b.qsize() > 0, "remaining subscriber must still receive events"

    asyncio.run(_run())


def test_remove_subscriber_is_idempotent(tmp_path: Path) -> None:
    """Calling ``remove_subscriber`` twice (or for unknown scan) is a no-op."""
    store = ScanStore(root_dir=tmp_path)

    async def _run() -> None:
        q = store.event_queue("scan-idem")
        # First removal succeeds.
        store.remove_subscriber("scan-idem", q)
        # Second removal of the same queue: no exception.
        store.remove_subscriber("scan-idem", q)
        # Unknown scan id: no exception.
        store.remove_subscriber("never-existed", q)
        # Empty bucket cleaned up.
        assert "scan-idem" not in store._subscribers

    asyncio.run(_run())


def test_remove_subscriber_cleans_empty_bucket(tmp_path: Path) -> None:
    """Last subscriber removal drops the ``_subscribers[scan_id]`` entry.

    Prevents one-key-per-historical-scan accumulation in a long-running
    uvicorn process.
    """
    store = ScanStore(root_dir=tmp_path)

    async def _run() -> None:
        q_a = store.event_queue("scan-bucket")
        q_b = store.event_queue("scan-bucket")
        assert "scan-bucket" in store._subscribers
        store.remove_subscriber("scan-bucket", q_a)
        assert "scan-bucket" in store._subscribers  # still B
        store.remove_subscriber("scan-bucket", q_b)
        assert "scan-bucket" not in store._subscribers  # bucket cleaned

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Acceptance 4 -- late-attach subscriber gets the buffered deque replay
# ---------------------------------------------------------------------------


def test_late_subscriber_replays_buffered_events(tmp_path: Path) -> None:
    """A subscriber attaching mid-scan gets the in-memory deque history first.

    Before the live drain starts, the new queue is pre-loaded with every
    event the deque still holds (each carrying its observer-stamped
    ``seq`` from Step 2.1) so the consumer can rebuild state without
    falling back to the on-disk JSONL.
    """
    store = ScanStore(root_dir=tmp_path)
    fake = _FakeSwarm()
    store.register("scan-late", fake)  # type: ignore[arg-type]

    # Emit some events BEFORE any consumer attaches.
    fake.observer(_event("agent_start"))  # type: ignore[misc]
    fake.observer(_event("agent_progress"))  # type: ignore[misc]
    fake.observer(_event("agent_done"))  # type: ignore[misc]

    async def _attach_and_drain() -> list[SwarmEvent]:
        q = store.event_queue("scan-late")
        out: list[SwarmEvent] = []
        while not q.empty():
            out.append(q.get_nowait())
        return out

    replayed = asyncio.run(_attach_and_drain())
    assert [e.kind for e in replayed] == ["agent_start", "agent_progress", "agent_done"]
    assert [e.seq for e in replayed] == [0, 1, 2]


def test_late_subscriber_does_not_steal_from_earlier_subscriber(tmp_path: Path) -> None:
    """The deque replay onto a new subscriber must not drain an existing one.

    Each subscriber gets its OWN copy of the buffered history; one tab's
    late-attach can't yank events from a tab that was already listening.
    """
    store = ScanStore(root_dir=tmp_path)
    fake = _FakeSwarm()
    store.register("scan-share", fake)  # type: ignore[arg-type]

    # Tab A attaches first, then 3 events fire.
    q_a = store.event_queue("scan-share")
    for _ in range(3):
        fake.observer(_event("agent_progress"))  # type: ignore[misc]

    # Tab B attaches AFTER -- should get the buffered 3 via deque replay.
    q_b = store.event_queue("scan-share")

    # Both queues see the same 3 events independently.
    a_seqs = []
    while not q_a.empty():
        a_seqs.append(q_a.get_nowait().seq)
    b_seqs = []
    while not q_b.empty():
        b_seqs.append(q_b.get_nowait().seq)
    assert a_seqs == [0, 1, 2]
    assert b_seqs == [0, 1, 2]
