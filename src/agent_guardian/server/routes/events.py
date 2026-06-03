"""GET /scan/{id}/events — SSE event stream."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_scan_store
from agent_guardian.server.sse import stream_scan_events

__all__ = ["router"]

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])


@router.get("/scan/{scan_id}/events")
async def events_stream(request: Request, scan_id: str) -> StreamingResponse:
    """Stream :class:`SwarmEvent` records as Server-Sent Events.

    The response stays open until the scan emits ``scan_done`` or the
    client disconnects. For completed scans that have an on-disk
    ``events.jsonl`` we replay every event then emit a synthetic
    ``scan_done`` terminator so the client knows to close.
    """
    store = get_scan_store(request)
    if not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")

    headers = {
        # SSE-friendly headers — disable any intermediary buffering.
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    # Phase 2 Step 2.1 — W3C EventSource resume protocol. The browser
    # sends the last ``id:`` it saw via the ``Last-Event-ID`` header on
    # reconnect; we filter out any event with ``seq <= last_event_id`` in
    # ``stream_scan_events`` so the client never sees a duplicate.
    last_event_id = request.headers.get("last-event-id")
    return StreamingResponse(
        stream_scan_events(scan_id, store, last_event_id=last_event_id),
        media_type="text/event-stream",
        headers=headers,
    )
