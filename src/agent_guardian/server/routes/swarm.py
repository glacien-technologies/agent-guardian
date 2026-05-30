"""GET /scan/{id}/swarm — live SVG swarm-graph view."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["router"]

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])


# The 11 satellite agents in fixed slot order — keeps the SVG layout
# stable across scans and matches the eleven-agent slate from PRD §3.
_AGENT_SLATE: tuple[tuple[str, str], ...] = (
    ("recon-agent", "Recon"),
    ("goal-hijack-agent", "Goal Hijack"),
    ("tool-abuse-agent", "Tool Abuse"),
    ("privilege-agent", "Privilege"),
    ("supply-chain-agent", "Supply Chain"),
    ("code-exec-agent", "Code Exec"),
    ("memory-poison-agent", "Memory Poison"),
    ("a2a-agent", "A2A"),
    ("cascade-agent", "Cascade"),
    ("trust-exploit-agent", "Trust Exploit"),
    ("drift-agent", "Drift"),
)


@router.get("/scan/{scan_id}/swarm", response_class=HTMLResponse)
async def swarm_view(request: Request, scan_id: str) -> HTMLResponse:
    """Render the live SVG swarm graph."""
    store = get_scan_store(request)
    templates = get_templates(request)
    scan = store.load_completed(scan_id)
    if scan is None and not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    return templates.TemplateResponse(
        request,
        "swarm.html",
        {
            "scan_id": scan_id,
            "scan": scan,
            "agents": _AGENT_SLATE,
            "page_title": f"Swarm — {scan_id}",
        },
    )
