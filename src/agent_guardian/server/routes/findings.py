"""GET /scan/{id}/findings — findings drill-down view."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from agent_guardian.models.asi import AsiCategory
from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["router"]

router = APIRouter()


@router.get("/scan/{scan_id}/findings", response_class=HTMLResponse)
async def findings_view(request: Request, scan_id: str, asi: str | None = None) -> HTMLResponse:
    """List findings for a scan, optionally filtered by ASI category."""
    store = get_scan_store(request)
    templates = get_templates(request)
    scan = store.load_completed(scan_id)
    if scan is None and not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    asi_filter: AsiCategory | None = None
    if asi:
        try:
            asi_filter = AsiCategory(asi)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"unknown ASI: {asi}") from exc

    findings = []
    if scan is not None:
        findings = (
            [f for f in scan.findings if f.asi is asi_filter]
            if asi_filter is not None
            else list(scan.findings)
        )

    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "scan_id": scan_id,
            "scan": scan,
            "findings": findings,
            "asi_filter": asi_filter.value if asi_filter else None,
            "asi_categories": list(AsiCategory),
            "page_title": f"Findings — {scan_id}",
        },
    )
