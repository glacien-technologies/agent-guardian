"""GET /analytics -- public community analytics dashboard.

Renders the day-1 minimum-viable analytics page from the PRD: the 4
hero numbers, the AIVSS distribution histogram, adapter mix, per-ASI
breakdown, Python x OS matrix, and the real-time scan ticker.

JSON endpoints back every cell so external embeds and CI badges can
hit them without scraping HTML:

* ``/api/analytics/hero.json``
* ``/api/analytics/aivss/distribution.json``
* ``/api/analytics/adapters.json``
* ``/api/analytics/asi.json``
* ``/api/analytics/python-os.json``
* ``/api/analytics/recent.json``
* ``/api/analytics/ingest`` -- POST collector endpoint (v1 schema)

All public endpoints honour the ``window`` query param: ``7d`` /
``30d`` (default) / ``365d`` / ``all``.

The collector endpoint is intentionally on the same FastAPI app for
the OSS reference deployment -- production would route this through a
separate ingestion service, but the route handler is the same code.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from agent_guardian.server.analytics import Aggregator, EventStore
from agent_guardian.server.routes._deps import get_templates
from agent_guardian.telemetry.events import EventEnvelope

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter()


_WINDOWS: dict[str, int] = {
    "24h": 1,
    "7d": 7,
    "30d": 30,
    "365d": 365,
    "all": 0,
}


def _resolve_window(window: str) -> int:
    if window not in _WINDOWS:
        raise HTTPException(
            status_code=400,
            detail=f"unknown window {window!r}; must be one of {sorted(_WINDOWS)}",
        )
    return _WINDOWS[window]


def _store_path() -> Path:
    """Resolve the on-disk SQLite store. Honours an env override for tests."""
    override = os.environ.get("AGENT_GUARDIAN_ANALYTICS_DB")
    if override:
        return Path(override)
    return Path.home() / ".agentguardian" / "analytics.db"


def _agg() -> tuple[Aggregator, EventStore]:
    store = EventStore(_store_path())
    return Aggregator(store.connection()), store


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@router.get("/analytics", response_class=HTMLResponse)
async def analytics_view(request: Request, window: str = "30d") -> HTMLResponse:
    """Render the public community analytics dashboard."""
    window_days = _resolve_window(window)
    agg, store = _agg()
    hero = agg.hero_numbers(window_days=window_days)
    histogram = agg.aivss_distribution(window_days=window_days)
    adapters = agg.adapter_mix(window_days=window_days)
    asi = agg.asi_breakdown(window_days=window_days)
    py_os = agg.python_os_matrix(window_days=window_days)
    recent = agg.recent_scans(limit=5)
    templates = get_templates(request)
    return templates.TemplateResponse(
        request,
        "analytics.html",
        {
            "page_title": "Community Analytics",
            "window": window,
            "window_label": _window_label(window),
            "hero": hero,
            "histogram": histogram,
            "max_bucket_pct": max((b.percent for b in histogram), default=1.0),
            "adapters": adapters,
            "asi": asi,
            "py_os": py_os,
            "recent": recent,
            "total_in_store": store.row_count(),
        },
    )


def _window_label(window: str) -> str:
    return {
        "24h": "Last 24 hours",
        "7d": "Last 7 days",
        "30d": "Last 30 days",
        "365d": "Last 365 days",
        "all": "All time",
    }[window]


# ---------------------------------------------------------------------------
# JSON endpoints
# ---------------------------------------------------------------------------


@router.get("/api/analytics/hero.json")
async def hero_json(window: str = "30d") -> JSONResponse:
    agg, _ = _agg()
    h = agg.hero_numbers(window_days=_resolve_window(window))
    return JSONResponse(
        {
            "window": window,
            "total_scans": h.total_scans,
            "median_aivss": h.median_aivss,
            "crash_free_rate_pct": h.crash_free_rate_pct,
            "monthly_active_installs": h.monthly_active_installs,
        }
    )


@router.get("/api/analytics/aivss/distribution.json")
async def distribution_json(window: str = "30d") -> JSONResponse:
    agg, _ = _agg()
    hist = agg.aivss_distribution(window_days=_resolve_window(window))
    return JSONResponse(
        {
            "window": window,
            "buckets": [
                {"lower": b.lower, "upper": b.upper, "count": b.count, "percent": b.percent}
                for b in hist
            ],
        }
    )


@router.get("/api/analytics/adapters.json")
async def adapters_json(window: str = "30d") -> JSONResponse:
    agg, _ = _agg()
    rows = agg.adapter_mix(window_days=_resolve_window(window))
    return JSONResponse(
        {
            "window": window,
            "rows": [
                {
                    "adapter": r.adapter,
                    "scans": r.scans,
                    "percent": r.percent,
                    "median_aivss": r.median_aivss,
                }
                for r in rows
            ],
        }
    )


@router.get("/api/analytics/asi.json")
async def asi_json(window: str = "30d") -> JSONResponse:
    agg, _ = _agg()
    rows = agg.asi_breakdown(window_days=_resolve_window(window))
    return JSONResponse(
        {
            "window": window,
            "rows": [
                {
                    "asi": r.asi,
                    "label": r.label,
                    "failure_rate_pct": r.failure_rate_pct,
                    "scans": r.scans,
                }
                for r in rows
            ],
        }
    )


@router.get("/api/analytics/python-os.json")
async def python_os_json(window: str = "30d") -> JSONResponse:
    agg, _ = _agg()
    cells = agg.python_os_matrix(window_days=_resolve_window(window))
    return JSONResponse({"window": window, "cells": cells})


@router.get("/api/analytics/recent.json")
async def recent_json(limit: int = 5) -> JSONResponse:
    agg, _ = _agg()
    limit = max(1, min(limit, 50))
    return JSONResponse({"recent": agg.recent_scans(limit=limit)})


# ---------------------------------------------------------------------------
# Collector POST endpoint (v1)
# ---------------------------------------------------------------------------


@router.post("/api/telemetry/v1/events", status_code=202)
async def ingest_event(envelope: EventEnvelope) -> dict[str, str]:
    """Collector endpoint. Accepts one envelope per request.

    Returns 202 Accepted on success, 400 on schema rejection (Pydantic
    catches that before we get here), 422 on clock-skew rejection or
    non-persistable event type.
    """
    _, store = _agg()
    ok = store.ingest(envelope)
    if not ok:
        _LOG.info(
            "analytics ingest: rejecting envelope event_type=%s (clock-skew or unsupported type)",
            envelope.event.event_type,
        )
        raise HTTPException(
            status_code=422,
            detail=(
                f"envelope rejected: event_type {envelope.event.event_type} not persisted "
                "by v1.0 collector OR client_sent_at failed clock-skew check"
            ),
        )
    return {"status": "accepted"}
