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
from collections.abc import AsyncIterator
from typing import Any

from agent_guardian.core.swarm import SwarmEvent
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


def format_sse_event(kind: str, data: dict[str, Any]) -> str:
    """Render one event to the SSE wire format.

    A trailing blank line terminates the event. The data is encoded as
    a single ``data:`` line because the payload is always one JSON
    object — no multi-line escaping needed.
    """
    payload = json.dumps(data, separators=(",", ":"))
    return f"event: {kind}\ndata: {payload}\n\n"


async def stream_scan_events(
    scan_id: str,
    store: ScanStore,
    *,
    is_disconnected: AsyncIterator[bool] | None = None,
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
    """
    queue = store.event_queue(scan_id)
    # Hot-replay of the running scan's history is already enqueued by the
    # ``event_queue`` call above; nothing extra to do for the live case.
    # If the scan is no longer running and we have no buffered events
    # either, fall back to the on-disk JSONL. We yield each event then a
    # synthetic terminator if the disk replay didn't include one.
    if not store.is_running(scan_id) and queue.empty():
        on_disk = store.replay_events_from_disk(scan_id)
        seen_done = False
        for payload in on_disk:
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
    while True:
        try:
            event: SwarmEvent = await asyncio.wait_for(
                queue.get(), timeout=_QUEUE_POLL_INTERVAL_SECONDS
            )
        except asyncio.TimeoutError:
            seconds_since_event += _QUEUE_POLL_INTERVAL_SECONDS
            if seconds_since_event >= _KEEPALIVE_INTERVAL_SECONDS:
                # SSE comment-only keepalive (line starting with ``:``).
                yield ": keepalive\n\n"
                seconds_since_event = 0.0
            continue
        seconds_since_event = 0.0
        payload = event_to_payload(event)
        yield format_sse_event(event.kind, payload)
        if event.kind == "scan_done":
            return
