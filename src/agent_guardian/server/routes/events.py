"""GET /scan/{id}/events — SSE event stream."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from agent_guardian.server.routes._deps import get_scan_store
from agent_guardian.server.sse import stream_scan_events

__all__ = ["router"]

router = APIRouter()


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
    return StreamingResponse(
        stream_scan_events(scan_id, store),
        media_type="text/event-stream",
        headers=headers,
    )
