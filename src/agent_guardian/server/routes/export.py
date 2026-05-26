"""GET /scan/{id}/export — links + raw report downloads."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["router"]

router = APIRouter()


_FORMAT_MEDIATYPES: dict[str, str] = {
    "json": "application/json",
    "sarif": "application/sarif+json",
    "junit": "application/xml",
    "md": "text/markdown",
}


@router.get("/scan/{scan_id}/export", response_class=HTMLResponse)
async def export_index(request: Request, scan_id: str) -> HTMLResponse:
    """Render the per-format export page (download links)."""
    store = get_scan_store(request)
    templates = get_templates(request)
    if not store.scan_dir(scan_id).is_dir() and not store.is_running(scan_id):
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    formats = store.list_report_paths(scan_id)
    return templates.TemplateResponse(
        request,
        "export.html",
        {
            "scan_id": scan_id,
            "formats": sorted(formats.keys()),
            "page_title": f"Export — {scan_id}",
        },
    )


@router.get("/scan/{scan_id}/export/{fmt}")
async def export_download(request: Request, scan_id: str, fmt: str) -> FileResponse:
    """Stream a single rendered report file."""
    store = get_scan_store(request)
    if fmt not in _FORMAT_MEDIATYPES:
        raise HTTPException(status_code=400, detail=f"unknown format: {fmt}")
    paths = store.list_report_paths(scan_id)
    path = paths.get(fmt)
    if path is None or not path.is_file():
        raise HTTPException(status_code=404, detail=f"report not available: {fmt}")
    return FileResponse(
        path=path,
        media_type=_FORMAT_MEDIATYPES[fmt],
        filename=f"{scan_id}.{fmt}",
    )
