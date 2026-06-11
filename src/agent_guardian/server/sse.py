"""Server-Sent Events plumbing for the M12 dashboard.

The dashboard subscribes to ``GET /scan/{id}/events`` and receives an
``text/event-stream`` response. Every line follows the PRD §9.5 wire
format::

    event: <event_kind>
    data: <json payload>

    event: scan_done
    data: {...}

The stream closes naturally when a ``scan_done`` event is emitted, or
when the client disconnects.

Implementation note — we deliberately do NOT add ``sse-starlette`` as a
dependency. FastAPI's :class:`fastapi.responses.StreamingResponse` is
sufficient for the simple framing the dashboard needs. See the
implementation plan §11.2.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.logging_setup import sanitize_for_log
from agent_guardian.server.partial_scan import is_terminal_scan_on_disk
from agent_guardian.server.scan_store import ScanStore, event_to_payload

__all__ = ["format_sse_event", "stream_scan_events"]

_LOG = logging.getLogger(__name__)

# Wait this long between queue polls when checking for client
# disconnects. Short enough to feel responsive, long enough to not
# burn CPU.
_QUEUE_POLL_INTERVAL_SECONDS = 0.5
# After this many seconds with no events, send a keep-alive comment so
# intermediaries don't drop the connection.
_KEEPALIVE_INTERVAL_SECONDS = 15.0
# SSE Phase 1, Step 5 — server-side data heartbeat. EventSource
# ``onmessage`` does NOT fire on ``:`` comment-only keepalives, so the
# client's freshness dot cannot use the keepalive line to refresh its
# ``lastEventAt`` clock (critic patch G14/P5 of
# designs/sse-flow-and-live-ui.md). We emit a real ``event: heartbeat``
# alongside the ``:`` comment so the dot can recolor on healthy quiet
# phases.
_HEARTBEAT_INTERVAL_SECONDS = 10.0


def format_sse_event(kind: str, data: dict[str, Any], *, seq: int | None = None) -> str:
    """Render one event to the SSE wire format.

    A trailing blank line terminates the event. The data is encoded as
    a single ``data:`` line because the payload is always one JSON
    object — no multi-line escaping needed.

    Phase 2 Step 2.1 — when ``seq`` is provided (or ``data`` carries a
    top-level ``"seq"`` integer), an ``id: <seq>`` line is prepended per
    the W3C EventSource spec. The browser then stamps its internal
    ``lastEventId`` and sends it back as the ``Last-Event-ID`` header on
    reconnect. Legacy events (no ``seq``) skip the id line so older
    snapshot replay paths keep their existing wire format.
    """
    payload = json.dumps(data, separators=(",", ":"))
    if seq is None:
        # Fall back to a top-level ``seq`` in the payload dict so callers
        # that already serialised via ``event_to_payload`` (which puts
        # ``seq`` at the top level) get the id line for free.
        candidate = data.get("seq") if isinstance(data, dict) else None
        if isinstance(candidate, int):
            seq = candidate
    if seq is not None:
        return f"id: {seq}\nevent: {kind}\ndata: {payload}\n\n"
    return f"event: {kind}\ndata: {payload}\n\n"


def _parse_last_event_id(raw: str | int | None) -> int | None:
    """Parse a ``Last-Event-ID`` header value to an int, or return None.

    Per the W3C EventSource spec the browser echoes whatever the server
    sent on the most recent ``id:`` line. We only stamp integer seq
    values, so a non-numeric value (e.g. a stale id from a different
    server build) is silently treated as absent — the stream replays
    from the start.
    """
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


async def stream_scan_events(
    scan_id: str,
    store: ScanStore,
    *,
    is_disconnected: AsyncIterator[bool] | None = None,
    last_event_id: str | int | None = None,
) -> AsyncIterator[str]:
    """Async generator yielding SSE-formatted strings for one scan.

    Order of operations:

    1. If the scan has on-disk replay events but is no longer running,
       yield them in order and finish with a synthetic ``scan_done``
       (driven by the last event we wrote).
    2. Otherwise wire up the live :class:`asyncio.Queue` from the
       store and yield events as they arrive.

    The ``is_disconnected`` parameter is an optional async iterator
    that yields ``True`` when the client has dropped the connection.
    For the FastAPI route we pass a small wrapper around
    :meth:`fastapi.Request.is_disconnected`. The tests pass ``None``
    and rely on the ``scan_done`` event to terminate the stream.

    Phase 2 Step 2.1 — ``last_event_id`` accepts the value of the
    HTTP ``Last-Event-ID`` request header (a string when supplied by a
    real browser, an int when supplied by a test). When numeric, events
    whose ``seq <= last_event_id`` are filtered out from BOTH the
    on-disk replay path and the live queue drain so a reconnecting
    client never sees an event it already processed. Events without a
    ``seq`` (legacy / unsequenced) are passed through unfiltered.
    """
    _LOG.debug("sse: opening event stream for scan_id=%s", sanitize_for_log(scan_id))  # noqa: py/log-injection  -- sanitize_for_log strips control chars + caps length
    resume_from = _parse_last_event_id(last_event_id)
    # Phase 2 Step 2.2 — per-subscriber queue. ``event_queue`` now
    # materialises a NEW queue on every call (multi-tab multicast). The
    # generator MUST detach the queue on close (try/finally below) so a
    # dropped consumer doesn't leak its queue into the observer fan-out.
    queue = store.event_queue(scan_id)
    # Hot-replay of the running scan's history is already enqueued by the
    # ``event_queue`` call above; nothing extra to do for the live case.
    # If the scan is no longer running and we have no buffered events
    # either, fall back to the on-disk JSONL. We yield each event then a
    # synthetic terminator if the disk replay didn't include one.
    try:
        scan_dir = store.scan_dir(scan_id)
        # #138 — cross-process disk-tail detection.
        #
        # The CLI-spawned dashboard runs in a SEPARATE process from the CLI
        # itself: the per-scan asyncio.Queue + in-memory ``_running``
        # registry are LOCAL to this store, so events the CLI emits go to
        # the CLI's queue and never reach this subprocess. Without the
        # branch below, ``is_running`` returns True (because
        # ``scan.partial.json`` is on disk) and we fall through to the
        # queue-listening loop — which sits forever on an empty queue,
        # emitting heartbeats but no events. Net effect: the dashboard
        # appears stuck despite the scan actively producing findings.
        #
        # Detect that case: scan_dir is present, ``_running`` does NOT
        # contain it (cross-process), and the terminal scan file has not
        # been written yet. When all three hold, switch to disk-tail mode
        # — replay everything on disk + poll events.jsonl for new lines —
        # and only emit the terminator once ``scan.raw.json`` /
        # ``scan.json`` lands.
        same_process_registered = scan_id in store._running
        # Any scan_dir without a terminal file is treated as in-flight in
        # cross-process mode. Pre-fix this branch ALSO required
        # ``scan.partial.json`` to be on disk — but ``partial.json`` is
        # written only on the first ``agent_done`` (typically ~30 s after
        # the scan starts), so a fresh tab opened during the cold window
        # fell through to the legacy synthetic-``scan_done`` branch and
        # the dashboard closed its EventSource before any real findings
        # ever arrived. Dropping the partial requirement keeps the
        # connection tailing through the cold window.
        cross_process_in_flight = (
            not same_process_registered
            and scan_dir.is_dir()
            and not is_terminal_scan_on_disk(scan_dir)
        )

        if cross_process_in_flight:
            last_seq_yielded: int = resume_from if resume_from is not None else -1
            seen_done = False

            # Initial replay of every event already on disk.
            for payload in store.replay_events_from_disk(scan_id):
                seq_val = payload.get("seq")
                if isinstance(seq_val, int):
                    if seq_val <= last_seq_yielded:
                        if payload.get("kind") == "scan_done":
                            seen_done = True
                        continue
                    last_seq_yielded = seq_val
                yield format_sse_event(payload.get("kind", "agent_progress"), payload)
                if payload.get("kind") == "scan_done":
                    seen_done = True

            terminal_on_disk = is_terminal_scan_on_disk(scan_dir)
            if terminal_on_disk or seen_done:
                # Genuinely-completed scan: ensure we sent the terminator
                # then close the stream.
                if not seen_done:
                    yield format_sse_event(
                        "scan_done",
                        {
                            "kind": "scan_done",
                            "agent": None,
                            "asi": None,
                            "provisional_aivss": None,
                            "decision": None,
                            "timestamp": "",
                            "payload": {"replay": True},
                        },
                    )
                return

            # Cross-process in-flight: tail events.jsonl on a poll until
            # the terminal scan file lands. Heartbeats keep the browser
            # connection alive during quiet phases.
            seconds_since_event = 0.0
            seconds_since_heartbeat = 0.0
            while True:
                # Cooperative disconnect check — only the FastAPI route
                # supplies this iterator; tests pass None.
                if is_disconnected is not None:
                    try:
                        dropped = await is_disconnected.__anext__()
                    except (StopAsyncIteration, AttributeError):
                        dropped = False
                    if dropped:
                        return

                # Drain any new events from events.jsonl. Mirror the
                # initial-replay logic exactly: events without an int seq
                # are still yielded (the initial replay at line 188-198
                # passes them through), so the poll loop must too —
                # otherwise unsequenced events would be silently dropped
                # only after the cold window, leaving the dashboard
                # apparently stuck while events keep arriving on disk.
                new_events: list[dict[str, Any]] = []
                for payload in store.replay_events_from_disk(scan_id):
                    seq_val = payload.get("seq")
                    if isinstance(seq_val, int) and seq_val <= last_seq_yielded:
                        continue
                    new_events.append(payload)
                if new_events:
                    for payload in new_events:
                        seq_val = payload.get("seq")
                        if isinstance(seq_val, int):
                            last_seq_yielded = seq_val
                        yield format_sse_event(payload.get("kind", "agent_progress"), payload)
                        if payload.get("kind") == "scan_done":
                            seen_done = True
                    seconds_since_event = 0.0
                    seconds_since_heartbeat = 0.0
                else:
                    seconds_since_event += _QUEUE_POLL_INTERVAL_SECONDS
                    seconds_since_heartbeat += _QUEUE_POLL_INTERVAL_SECONDS

                # Terminal scan file landed? Wrap up.
                if is_terminal_scan_on_disk(scan_dir):
                    # One final disk drain so we don't miss the very last
                    # events that landed between the previous drain and
                    # the terminal file write.
                    for payload in store.replay_events_from_disk(scan_id):
                        seq_val = payload.get("seq")
                        if not isinstance(seq_val, int) or seq_val <= last_seq_yielded:
                            continue
                        last_seq_yielded = int(seq_val)
                        yield format_sse_event(payload.get("kind", "agent_progress"), payload)
                        if payload.get("kind") == "scan_done":
                            seen_done = True
                    if not seen_done:
                        yield format_sse_event(
                            "scan_done",
                            {
                                "kind": "scan_done",
                                "agent": None,
                                "asi": None,
                                "provisional_aivss": None,
                                "decision": None,
                                "timestamp": "",
                                "payload": {"replay": True, "from_terminal_file": True},
                            },
                        )
                    return

                # Heartbeats during quiet windows — mirrors the same-process
                # branch below so the client freshness dot can stay green.
                if seconds_since_heartbeat >= _HEARTBEAT_INTERVAL_SECONDS:
                    yield format_sse_event("heartbeat", {"now": time.time()})
                    seconds_since_heartbeat = 0.0
                if seconds_since_event >= _KEEPALIVE_INTERVAL_SECONDS:
                    yield ": keepalive\n\n"
                    seconds_since_event = 0.0

                await asyncio.sleep(_QUEUE_POLL_INTERVAL_SECONDS)

            # Unreachable; the loop only exits via `return`.

        # Original disk-replay branch for completed scans whose terminator
        # is missing from disk (tests + legacy / abnormal-exit recovery).
        if not store.is_running(scan_id) and queue.empty():
            on_disk = store.replay_events_from_disk(scan_id)
            seen_done = False
            for payload in on_disk:
                if resume_from is not None:
                    seq_val = payload.get("seq")
                    if isinstance(seq_val, int) and seq_val <= resume_from:
                        if payload.get("kind") == "scan_done":
                            seen_done = True
                        continue
                yield format_sse_event(payload.get("kind", "agent_progress"), payload)
                if payload.get("kind") == "scan_done":
                    seen_done = True
            if not seen_done:
                yield format_sse_event(
                    "scan_done",
                    {
                        "kind": "scan_done",
                        "agent": None,
                        "asi": None,
                        "provisional_aivss": None,
                        "decision": None,
                        "timestamp": "",
                        "payload": {"replay": True},
                    },
                )
            return

        seconds_since_event = 0.0
        seconds_since_heartbeat = 0.0
        while True:
            try:
                event: SwarmEvent = await asyncio.wait_for(
                    queue.get(), timeout=_QUEUE_POLL_INTERVAL_SECONDS
                )
            except TimeoutError:
                seconds_since_event += _QUEUE_POLL_INTERVAL_SECONDS
                seconds_since_heartbeat += _QUEUE_POLL_INTERVAL_SECONDS
                if seconds_since_heartbeat >= _HEARTBEAT_INTERVAL_SECONDS:
                    # SSE data heartbeat — EventSource ``onmessage`` (or a
                    # typed ``heartbeat`` listener) fires on this so the
                    # client freshness dot can refresh ``lastEventAt`` on
                    # healthy quiet phases. Critic patch G14/P5.
                    yield format_sse_event("heartbeat", {"now": time.time()})
                    seconds_since_heartbeat = 0.0
                if seconds_since_event >= _KEEPALIVE_INTERVAL_SECONDS:
                    # SSE comment-only keepalive (line starting with ``:``).
                    # Kept for HTTP intermediaries that drop idle connections;
                    # the browser EventSource does NOT fire ``onmessage`` on
                    # these so it cannot drive the freshness clock.
                    yield ": keepalive\n\n"
                    seconds_since_event = 0.0
                continue
            seconds_since_event = 0.0
            seconds_since_heartbeat = 0.0
            # Phase 2 Step 2.1 — Last-Event-ID resume filter on the live
            # queue drain. The buffered-replay path in ``event_queue`` does
            # NOT pre-filter (it's a generic queue plumber), so we filter
            # here so a reconnecting client never sees a duplicate event.
            if resume_from is not None and event.seq is not None and event.seq <= resume_from:
                # Still respect the terminal — a scan_done filtered out
                # would otherwise leave the generator looping forever.
                if event.kind == "scan_done":
                    return
                continue
            payload = event_to_payload(event)
            yield format_sse_event(event.kind, payload)
            if event.kind == "scan_done":
                return
    finally:
        # Phase 2 Step 2.2 — explicit cleanup: detach our queue from the
        # store's subscriber list so the observer fan-out doesn't keep
        # feeding events into an abandoned queue (memory leak prevention).
        # Idempotent on the store side; safe even if the stream never
        # ran (e.g. early-return via the disk-replay path above).
        store.remove_subscriber(scan_id, queue)
