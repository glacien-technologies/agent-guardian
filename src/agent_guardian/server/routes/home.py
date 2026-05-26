"""GET / — dashboard landing page with scan history."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["router"]

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    """Render the scan-history landing page."""
    store = get_scan_store(request)
    templates = get_templates(request)
    summaries = store.list_scans()
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "scans": summaries,
            "page_title": "Scan history",
        },
    )
