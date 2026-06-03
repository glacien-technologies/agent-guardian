"""GET /scan/{scan_id} + /scans/{scan_id} — live scan dashboard.

The legacy route ``/scan/<id>`` keeps the old short-form URL alive; the
canonical URL the CLI emits is ``/scans/<id>`` (note the trailing 's'),
which 307-redirects to the legacy short URL. Both paths land on the same
view-model so a bookmarked legacy URL still works.

Routes:

* ``GET /scan/{scan_id}`` — renders ``dashboard/executive/layout.html``
  (the only dashboard theme that ships now; the multi-theme switcher was
  retired in QA-041). ``?theme=`` query params are silently ignored.
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
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

from agent_guardian._version import __version__
from agent_guardian.logging_setup import sanitize_for_log
from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.dashboard_view import (
    DASHBOARD_TEMPLATE,
    _assemble_probes_list,
    build_dashboard_context,
    build_finding_slideover_ctx,
    live_snapshot,
)
from agent_guardian.server.partial_scan import is_terminal_scan_on_disk
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
# SSE Phase 1, Step 5 — emit a ``deadline_approaching`` event this many
# seconds before the live stream hits ``_LIVE_MAX_SECONDS`` so the
# client's freshness dot can suppress its DEAD/red transition for the
# clean reconnect that follows. Without this signal the dot pages
# operators every 30 minutes on healthy long-running scans (critic
# patch G5 / P-ScheduledReconnect of designs/sse-flow-and-live-ui.md).
_DEADLINE_APPROACHING_LEAD_SECONDS = 30.0


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
    dt = datetime.fromtimestamp(scan_dir_mtime, tz=UTC)
    return dt.strftime("%d %b %Y · %H:%M UTC")


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_view(request: Request, scan_id: str) -> HTMLResponse:
    """Render the Executive dashboard for a scan (legacy URL)."""
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
    # Elapsed clock: prefer wall-clock from the scan-dir mtime whenever the
    # scan is still in flight -- that covers both the in-process path
    # (``is_running=True`` from a library caller that used ``store.register``)
    # and the cross-process path (the dashboard subprocess sees only the
    # partial scan on disk and never gets ``register()``-d). The Scan's own
    # ``duration_seconds`` is the right source once the terminal file lands.
    terminal_on_disk = is_terminal_scan_on_disk(scan_dir)
    in_flight = is_running or (scan is not None and not terminal_on_disk)
    elapsed = max(0.0, time.time() - mtime) if (in_flight and mtime is not None) else None
    ctx = build_dashboard_context(
        scan_id=scan_id,
        scan=scan,
        is_running=is_running,
        base_url=base_url,
        version_label=__version__,
        elapsed_seconds=elapsed,
        started_at_label=started_label,
        page=page,
        is_terminal=terminal_on_disk and not is_running,
        scan_dir=scan_dir,
    )
    # QA-041: only the Executive theme ships. ``?theme=<anything>`` is
    # silently ignored so any stale bookmark still resolves to a usable
    # dashboard page rather than 404-ing.
    payload = ctx.to_dict()
    return templates.TemplateResponse(
        request,
        DASHBOARD_TEMPLATE,
        payload,
    )


@router.get("/scan/{scan_id}/probe", response_class=HTMLResponse)
async def probe_drawer(
    request: Request,
    scan_id: str,
    index: int | None = None,
    id: str | None = None,
) -> HTMLResponse:
    """Render the probe-detail-sheet drawer fragment for one probe.

    QA-049 / BUG-1 (2026-06-02) — the Probes-tab drawer is now loaded
    on demand instead of bundled into the initial page HTML. Each row
    in ``_probes_table.html`` carries a ``data-probe-href`` that points
    here; the shared slide-over JS ``fetch()``-es this endpoint and
    injects the response into ``.exec-slideover__body``.

    Lookup priority:

    * ``index=<N>`` — fast path, indexes into the assembled probes
      list (the table emits ``data-probe-index`` from
      ``loop.index0``). O(1) and stable across reloads.
    * ``id=<probe_id>`` — fallback used when a deep link / bookmark
      carries the probe id (``?tab=probes&probe=<id>``). O(N) scan.

    Returns a 404 (HTML fragment) when the scan exists but the probe
    can't be located; the drawer JS treats the empty body as "no
    matching probe" and leaves the previous open-state untouched.
    """
    store = get_scan_store(request)
    templates = get_templates(request)
    if not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")

    probes = _assemble_probes_list(store.scan_dir(scan_id))
    probe: dict[str, object] | None = None
    if index is not None and 0 <= index < len(probes):
        probe = probes[index]
    elif id:
        for p in probes:
            if p.get("probe_id") == id:
                probe = p
                break

    if probe is None:
        # Render an empty drawer-body shell — same structural class so
        # the drawer chrome stays consistent and the client-side CSS
        # selectors keep matching.
        return HTMLResponse(
            '<div class="exec-probe-detail-sheet" data-probe-detail-sheet>'
            '<p class="exec-probe__reason exec-probe__reason--empty">'
            "Probe not found in this scan's memory.jsonl."
            "</p></div>",
            status_code=200,
        )

    return templates.TemplateResponse(
        request,
        "dashboard/executive/_probe_drawer_body.html",
        {"probe": probe, "scan_id": scan_id},
    )


@router.get("/scan/{scan_id}/finding/{finding_id}", response_class=HTMLResponse)
async def finding_slideover(
    request: Request,
    scan_id: str,
    finding_id: str,
) -> HTMLResponse:
    """Render the finding slide-over body fragment for one Finding (QA-055).

    Sibling of :func:`probe_drawer` — together they form the QA-049 /
    QA-055 polymorphic loader contract: row click in either the
    Findings tab or the Probes tab triggers a ``fetch()`` against the
    matching ``/scan/<id>/{finding|probe}/<id>`` URL; the response is a
    server-rendered HTML fragment from the SHARED
    ``_slideover.html`` template (``kind="finding"`` here). The shared
    template carries the full audit detail (prompt + response +
    judge reasoning + per-turn thread + reproduce-CLI), so the
    operator sees the same level of detail regardless of which tab
    they opened the slide-over from.

    The Finding model itself doesn't carry verbatim prompt / response
    text — :func:`build_finding_slideover_ctx` joins against the
    correlated probe attempts in ``memory.jsonl`` to surface them. A
    finding with no correlated probe attempts renders the prompt /
    response / reasoning sections as ``(no data available)``
    placeholders.

    Returns 404 when the scan exists but the finding id can't be
    located; returns 404 when the scan itself is unknown.
    """
    store = get_scan_store(request)
    templates = get_templates(request)
    scan = store.load_completed(scan_id)
    if scan is None and not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    if scan is None:
        # Scan dir exists but no terminal report yet — findings are
        # only addressable post-finalize.
        raise HTTPException(status_code=404, detail=f"unknown finding: {finding_id}")

    finding = next((f for f in scan.findings if f.id == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"unknown finding: {finding_id}")

    ctx = build_finding_slideover_ctx(finding, scan_dir=store.scan_dir(scan_id))
    return templates.TemplateResponse(
        request,
        "dashboard/executive/_slideover.html",
        {"ctx": ctx, "scan_id": scan_id, "kind": "finding"},
    )


_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


@router.get("/scans/{scan_id}")
async def scans_redirect(request: Request, scan_id: str) -> RedirectResponse:
    """Canonical CLI-emitted URL. Always 307-redirects to ``/scan/{id}``."""
    # Validate scan_id against a strict allowlist before using it in a
    # redirect target — prevents open-redirect via crafted path segments
    # (e.g. ``//evil.com/`` or ``..%2F``).
    if not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="invalid scan id")
    store = get_scan_store(request)
    # We don't 404 here — the redirect target does, and we preserve any
    # query string so ``?page=2`` survives the bounce.
    if not store.is_running(scan_id) and not store.scan_dir(scan_id).is_dir():
        # Don't redirect into a known-404. Surface it now so curl doesn't
        # have to follow the bounce just to see the error.
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    # Rebuild the redirect target from server-validated components only.
    # ``scan_id`` is constrained by ``_SCAN_ID_RE`` above, and the query
    # string is re-encoded from parsed key/value pairs rather than spliced
    # verbatim from the request — closing the open-redirect vector that
    # CodeQL flags here (CWE-601).
    safe_qs = urlencode(list(request.query_params.multi_items()), doseq=True)
    target = f"/scan/{scan_id}" + (f"?{safe_qs}" if safe_qs else "")
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
                    _LOG.warning(  # noqa: py/log-injection  -- scan_id passed through sanitize_for_log; path is server-constructed
                        "scans_report: cannot read %s for %s (%s)",
                        path,
                        sanitize_for_log(scan_id),
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
        approaching_at = deadline - _DEADLINE_APPROACHING_LEAD_SECONDS
        approaching_fired = False
        last_snapshot: dict[str, object] | None = None
        while True:
            now = time.monotonic()
            if now > deadline:
                break
            # SSE Phase 1, Step 5 — pre-emit a ``deadline_approaching``
            # event 30 s before the soft cap. The client's
            # ``freshness-dot.js`` listens for this and suppresses its
            # red/DEAD transition for 60 s while the EventSource
            # reconnects, so the operator never sees a red dot on a
            # healthy 30-minute scan crossing.
            if not approaching_fired and now >= approaching_at:
                yield (
                    "event: deadline_approaching\n"
                    + "data: "
                    + json.dumps(
                        {"deadline_in_seconds": max(0.0, deadline - now)},
                        separators=(",", ":"),
                    )
                    + "\n\n"
                )
                approaching_fired = True
            is_running = store.is_running(scan_id)
            scan = store.load_completed(scan_id)
            scan_dir = store.scan_dir(scan_id)
            try:
                mtime = scan_dir.stat().st_mtime if scan_dir.is_dir() else None
            except OSError:
                mtime = None
            terminal_on_disk = is_terminal_scan_on_disk(scan_dir)
            in_flight = is_running or (scan is not None and not terminal_on_disk)
            elapsed = max(0.0, time.time() - mtime) if (in_flight and mtime is not None) else None
            ctx = build_dashboard_context(
                scan_id=scan_id,
                scan=scan,
                is_running=is_running,
                base_url=base_url,
                version_label=__version__,
                elapsed_seconds=elapsed,
                started_at_label=_started_at_label(mtime),
                is_terminal=terminal_on_disk and not is_running,
                scan_dir=scan_dir,
            )
            snapshot = live_snapshot(ctx)
            if snapshot != last_snapshot:
                yield f"event: snapshot\ndata: {json.dumps(snapshot, separators=(',', ':'))}\n\n"
                last_snapshot = snapshot
            # Stop the SSE stream once the terminal scan file has landed on
            # disk -- a partial mid-flight snapshot (scan.partial.json) keeps
            # the live updates flowing. Using the on-disk presence as the
            # terminal signal (rather than ``scoring_valid``) preserves the
            # SSE-end behaviour for legitimately-completed stub / non-
            # authoritative scans whose ``scoring_valid`` is False by design.
            if not is_running and scan is not None and terminal_on_disk:
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
