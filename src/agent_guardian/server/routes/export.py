"""GET /scan/{id}/export — links + raw report / artifact downloads."""

from __future__ import annotations

import contextlib
import io
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.posthog_client import get_posthog
from agent_guardian.server.routes._deps import get_scan_store
from agent_guardian.telemetry.install_id import get_install_id

__all__ = ["router"]

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])


_FORMAT_MEDIATYPES: dict[str, str] = {
    "json": "application/json",
    "sarif": "application/sarif+json",
    "junit": "application/xml",
    "md": "text/markdown",
}

# Raw per-scan artifacts the export page links for reference, with their
# media type + a short human label. Whitelisted by exact name so the download
# route can never be coerced into serving an arbitrary file.
_RAW_FILES: dict[str, tuple[str, str]] = {
    "run.log": ("text/plain; charset=utf-8", "Full raw log (every line)"),
    "events.jsonl": ("application/x-ndjson", "SSE event stream"),
    "memory.jsonl": ("application/x-ndjson", "Every turn / finding"),
    "recon_probes.jsonl": ("application/x-ndjson", "Recon probe log"),
    "scan.json": ("application/json", "Canonical signed scan"),
    "scan.raw.json": ("application/json", "Raw scan model dump"),
    "stats.json": ("application/json", "Scan stats"),
}


@router.get("/scan/{scan_id}/export/bundle.zip")
async def export_bundle(request: Request, scan_id: str) -> Response:
    """Stream ONE zip with every downloadable artifact for the scan.

    Bundles the rendered reports (``reports/<fmt>.<fmt>``), the per-agent probe
    records (``probe/<agent>.json``) and the whitelisted raw artifacts +
    logs (``raw/run.log`` / ``raw/events.jsonl`` / …) so an operator can grab
    the whole evidence pack in a single click instead of file-by-file.

    Declared BEFORE ``/scan/{scan_id}/export/{fmt}`` so the literal ``bundle.zip``
    path wins the route match rather than being read as ``fmt="bundle.zip"``.
    """
    store = get_scan_store(request)
    scan_dir = store.scan_dir(scan_id)
    if not scan_dir.is_dir() and not store.is_running(scan_id):
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Rendered reports → reports/<fmt>.<fmt> (json.json, sarif.sarif, …).
        for fmt, path in store.list_report_paths(scan_id).items():
            if path.is_file():
                zf.write(path, arcname=f"reports/{fmt}.{fmt}")
        # Per-agent probe records → probe/<name>.
        probe_dir = scan_dir / "probe"
        if probe_dir.is_dir():
            for p in sorted(probe_dir.glob("*.json")):
                zf.write(p, arcname=f"probe/{p.name}")
        # Whitelisted raw artifacts + logs → raw/<name>.
        for name in _RAW_FILES:
            p = scan_dir / name
            if p.is_file():
                zf.write(p, arcname=f"raw/{name}")

    ph = get_posthog(request.app)
    if ph is not None:
        with contextlib.suppress(Exception):
            ph.capture(get_install_id(), "export_bundle_downloaded")

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{scan_id}-bundle.zip"'},
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
    ph = get_posthog(request.app)
    if ph is not None:
        with contextlib.suppress(Exception):
            ph.capture(get_install_id(), "export_downloaded", {"format": fmt})

    return FileResponse(
        path=path,
        media_type=_FORMAT_MEDIATYPES[fmt],
        filename=f"{scan_id}.{fmt}",
    )


@router.get("/scan/{scan_id}/raw/{name}")
async def raw_download(request: Request, scan_id: str, name: str) -> FileResponse:
    """Stream a whitelisted raw per-scan artifact (run.log / events.jsonl / …)."""
    store = get_scan_store(request)
    media = _RAW_FILES.get(name)
    if media is None:
        raise HTTPException(status_code=400, detail=f"unknown artifact: {name}")
    path = store.scan_dir(scan_id) / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"artifact not available: {name}")
    return FileResponse(path=path, media_type=media[0], filename=f"{scan_id}-{name}")


@router.get("/scan/{scan_id}/probe-file/{name}")
async def probe_file_download(request: Request, scan_id: str, name: str) -> FileResponse:
    """Stream one per-agent probe JSON from ``<scan_dir>/probe/``.

    ``name`` is reduced to a bare basename and must end in ``.json`` and resolve
    inside the probe directory — no path traversal.
    """
    store = get_scan_store(request)
    from pathlib import Path

    safe = Path(name).name
    if not safe.endswith(".json"):
        raise HTTPException(status_code=400, detail="probe file must be .json")
    probe_dir = (store.scan_dir(scan_id) / "probe").resolve()
    path = (probe_dir / safe).resolve()
    if probe_dir not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail=f"probe record not available: {safe}")
    return FileResponse(path=path, media_type="application/json", filename=f"{scan_id}-{safe}")
