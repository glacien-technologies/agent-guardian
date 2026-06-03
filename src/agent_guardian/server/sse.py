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
        if not store.is_running(scan_id) and queue.empty():
            on_disk = store.replay_events_from_disk(scan_id)
            seen_done = False
            for payload in on_disk:
                # Phase 2 Step 2.1 — Last-Event-ID resume filter. Skip any
                # JSONL line whose top-level ``seq`` is <= the resume cursor.
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
