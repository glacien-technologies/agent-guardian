"""GET /about — methodology / citations / license."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_templates

__all__ = ["router"]

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])


@router.get("/about", response_class=HTMLResponse)
async def about(request: Request) -> HTMLResponse:
    templates = get_templates(request)
    return templates.TemplateResponse(
        request,
        "about.html",
        {"page_title": "About"},
    )
