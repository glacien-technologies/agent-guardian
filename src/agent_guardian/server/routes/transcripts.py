"""GET /scan/{id}/transcripts/{finding_id} — full transcript view."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from agent_guardian.core.redact import redact_finding
from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["router"]

router = APIRouter()


@router.get(
    "/scan/{scan_id}/transcripts/{finding_id}",
    response_class=HTMLResponse,
)
async def transcript_view(
    request: Request, scan_id: str, finding_id: str, redact: bool = True
) -> HTMLResponse:
    """Show the full transcript for one finding.

    When ``redact`` is true (the default) the finding's ``summary`` and
    ``transcript_ref`` are passed through :func:`redact_finding` BEFORE the
    template renders them, so PII and captured secrets never reach the browser.
    The "PII redaction: on" chip is only shown when redaction was actually
    applied -- the template renders the redacted finding, not the raw one.
    """
    store = get_scan_store(request)
    templates = get_templates(request)
    scan = store.load_completed(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    finding = next((f for f in scan.findings if f.id == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"unknown finding: {finding_id}")
    # Redact at the source before the template ever sees the fields.
    display_finding = redact_finding(finding, enabled=redact)
    return templates.TemplateResponse(
        request,
        "transcripts.html",
        {
            "scan_id": scan_id,
            "scan": scan,
            "finding": display_finding,
            "redact": redact,
            "page_title": f"Transcript — {finding_id}",
        },
    )
