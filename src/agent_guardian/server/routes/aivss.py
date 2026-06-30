"""GET /scan/{id}/aivss — AIVSS sub-score radar chart view."""

from __future__ import annotations

import contextlib
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.posthog_client import get_posthog
from agent_guardian.server.routes._deps import get_scan_store, get_templates
from agent_guardian.telemetry.install_id import get_install_id

__all__ = ["router"]

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])


@router.get("/scan/{scan_id}/aivss", response_class=HTMLResponse)
async def aivss_view(request: Request, scan_id: str) -> HTMLResponse:
    """Render the AIVSS sub-score radar chart."""
    store = get_scan_store(request)
    templates = get_templates(request)
    scan = store.load_completed(scan_id)
    if scan is None and not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    sub_scores = scan.sub_scores if scan is not None else {}
    # Stable ordering for the radar polygon.
    sub_score_order = [
        "prompt_injection_resistance",
        "tool_scope_safety",
        "pii_containment",
        "memory_poisoning_resistance",
        "excessive_agency_containment",
        "hallucination_resistance",
    ]
    ordered = [(name, sub_scores.get(name, 0.0)) for name in sub_score_order]

    ph = get_posthog(request.app)
    if ph is not None:
        with contextlib.suppress(Exception):
            ph.capture(
                get_install_id(),
                "aivss_viewed",
                {"has_scores": scan is not None},
            )

    return templates.TemplateResponse(
        request,
        "aivss.html",
        {
            "scan_id": scan_id,
            "scan": scan,
            "sub_scores_ordered": ordered,
            "sub_scores_json": json.dumps([{"name": n, "score": v} for n, v in ordered]),
            "page_title": f"AIVSS — {scan_id}",
        },
    )
