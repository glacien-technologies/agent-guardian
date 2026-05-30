"""GET /scan/{scan_id} + /scans/{scan_id} — live scan dashboard.

The legacy route ``/scan/<id>`` keeps the old short-form URL alive
(rendering the new editorial dashboard template); the canonical URL the
CLI emits is ``/scans/<id>`` (note the trailing 's'), which 307-redirects
to the legacy short URL. Both paths land on the same view-model so a
bookmarked legacy URL still works.

Routes:

* ``GET /scan/{scan_id}`` — renders ``dashboard/scan_detail.html``.
* ``GET /scans/{scan_id}`` — 307 redirect to ``/scan/{scan_id}`` (the
  CLI-emitted canonical URL). The CLI is the contract holder.
* ``GET /scans/{scan_id}/report`` — canonical ``scan.json`` (200 when
  completed, 404 while running).
* ``GET /scans/{scan_id}/live`` — Server-Sent Events stream of
  ``snapshot`` events with the data-live=* keys.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

from agent_guardian._version import __version__
from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.dashboard_view import build_dashboard_context, live_snapshot
from agent_guardian.server.routes._deps import get_scan_store, get_templates

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])

# Live SSE poll interval. 500 ms is tight enough to feel live without
# burning CPU on a quiet scan.
_LIVE_POLL_SECONDS = 0.5
# Soft cap on a single SSE stream lifetime so a forgotten browser tab can't
# pin a uvicorn worker forever.
_LIVE_MAX_SECONDS = 1800.0


def _resolve_base_url(request: Request) -> str:
    """Resolve the dashboard base URL from env / request headers.

    The CLI sets ``$AGENT_GUARDIAN_DASHBOARD_URL`` for hosted deploys; when
    unset we synthesise the base from the current request so the locality
    pill displays the right host even on a non-default port.
    """
    env_base = os.environ.get("AGENT_GUARDIAN_DASHBOARD_URL")
    if env_base:
        return env_base.rstrip("/")
    return str(request.base_url).rstrip("/")


def _started_at_label(scan_dir_mtime: float | None) -> str:
    if scan_dir_mtime is None:
        return ""
    dt = datetime.fromtimestamp(scan_dir_mtime, tz=timezone.utc)
    return dt.strftime("%d %b %Y · %H:%M UTC")


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_view(request: Request, scan_id: str) -> HTMLResponse:
    """Render the editorial dashboard for a scan (legacy URL)."""
    store = get_scan_store(request)
    templates = get_templates(request)
    is_running = store.is_running(scan_id)
    scan = store.load_completed(scan_id)
    if scan is None and not is_running and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")

    scan_dir = store.scan_dir(scan_id)
    try:
        mtime = scan_dir.stat().st_mtime if scan_dir.is_dir() else None
    except OSError:
        mtime = None
    started_label = _started_at_label(mtime)

    page_param = request.query_params.get("page")
    try:
        page = max(1, int(page_param)) if page_param else 1
    except ValueError:
        page = 1

    base_url = _resolve_base_url(request)
    elapsed = max(0.0, time.time() - mtime) if (is_running and mtime is not None) else None
    ctx = build_dashboard_context(
        scan_id=scan_id,
        scan=scan,
        is_running=is_running,
        base_url=base_url,
        version_label=__version__,
        elapsed_seconds=elapsed,
        started_at_label=started_label,
        page=page,
    )
    return templates.TemplateResponse(
        request,
        "dashboard/scan_detail.html",
        ctx.to_dict(),
    )


@router.get("/scans/{scan_id}")
async def scans_redirect(request: Request, scan_id: str) -> RedirectResponse:
    """Canonical CLI-emitted URL. Always 307-redirects to ``/scan/{id}``."""
    store = get_scan_store(request)
    # We don't 404 here — the redirect target does, and we preserve any
    # query string so ``?page=2`` survives the bounce.
    if not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        # Don't redirect into a known-404. Surface it now so curl doesn't
        # have to follow the bounce just to see the error.
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    qs = request.url.query
    target = f"/scan/{scan_id}" + (f"?{qs}" if qs else "")
    return RedirectResponse(url=target, status_code=307)


@router.get("/scans/{scan_id}/report")
async def scans_report(request: Request, scan_id: str) -> JSONResponse:
    """Return the canonical ``scan.json`` payload for a completed scan."""
    store = get_scan_store(request)
    if not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    if store.is_running(scan_id):
        return JSONResponse(
            status_code=404,
            content={
                "detail": "scan still running, report not yet available",
                "status": "running",
            },
        )
    scan = store.load_completed(scan_id)
    if scan is None:
        # Directory exists but the scan.json couldn't be loaded — probably a
        # crashed run. Surface the raw file path if present so the operator
        # can inspect it.
        scan_dir = store.scan_dir(scan_id)
        for name in ("scan.raw.json", "scan.json"):
            path = scan_dir / name
            if path.is_file():
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    return JSONResponse(payload)
                except (OSError, json.JSONDecodeError) as exc:
                    _LOG.warning(
                        "scans_report: cannot read %s for %s (%s)",
                        path,
                        scan_id,
                        exc,
                    )
        raise HTTPException(status_code=404, detail=f"no report for scan: {scan_id}")
    return JSONResponse(json.loads(scan.model_dump_json()))


@router.get("/scans/{scan_id}/live")
async def scans_live_sse(request: Request, scan_id: str) -> StreamingResponse:
    """SSE stream of ``snapshot`` events for the dashboard's data-live nodes."""
    store = get_scan_store(request)
    if not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    base_url = _resolve_base_url(request)

    async def _gen() -> AsyncIterator[str]:
        deadline = time.monotonic() + _LIVE_MAX_SECONDS
        last_snapshot: dict[str, object] | None = None
        while True:
            if time.monotonic() > deadline:
                break
            is_running = store.is_running(scan_id)
            scan = store.load_completed(scan_id)
            scan_dir = store.scan_dir(scan_id)
            try:
                mtime = scan_dir.stat().st_mtime if scan_dir.is_dir() else None
            except OSError:
                mtime = None
            elapsed = max(0.0, time.time() - mtime) if (is_running and mtime is not None) else None
            ctx = build_dashboard_context(
                scan_id=scan_id,
                scan=scan,
                is_running=is_running,
                base_url=base_url,
                version_label=__version__,
                elapsed_seconds=elapsed,
                started_at_label=_started_at_label(mtime),
            )
            snapshot = live_snapshot(ctx)
            if snapshot != last_snapshot:
                yield f"event: snapshot\ndata: {json.dumps(snapshot, separators=(',', ':'))}\n\n"
                last_snapshot = snapshot
            if not is_running and scan is not None:
                yield "event: scan_done\ndata: {}\n\n"
                break
            try:
                await asyncio.sleep(_LIVE_POLL_SECONDS)
            except asyncio.CancelledError:  # pragma: no cover — client disconnect
                break

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(_gen(), media_type="text/event-stream", headers=headers)
