"""GET /scan/{scan_id} — main live-scan view."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["router"]

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_view(request: Request, scan_id: str) -> HTMLResponse:
    """Render the live scan view.

    Always 200 for a known scan (running or completed). 404 for an
    unknown ID. The page subscribes to ``/scan/{id}/events`` to fill in
    live state.
    """
    store = get_scan_store(request)
    templates = get_templates(request)
    is_running = store.is_running(scan_id)
    scan = store.load_completed(scan_id)
    if scan is None and not is_running and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "scan_id": scan_id,
            "is_running": is_running,
            "scan": scan,
            "page_title": f"Scan {scan_id}",
        },
    )
