"""FastAPI application factory for the M12 web dashboard.

The dashboard is a small, hand-authored FastAPI app that exposes the
running and historical scan state in a browser. It has no build step,
no CDN, and no extra runtime dependencies beyond what AgentGuardian
already ships.

Boot sequence
-------------

* :func:`create_app` constructs the :class:`FastAPI` instance.
* The eight route modules in :mod:`agent_guardian.server.routes` are
  imported and their ``router`` objects registered.
* The Jinja2 template environment is configured to read from
  ``server/templates/`` and given two globals -- ``version`` and a tiny
  helper ``url_for`` substitute we use to keep templates portable.
* ``server/static/`` is mounted at ``/static``.
* A :class:`ScanStore` is stashed on ``app.state.scan_store`` so
  route handlers can pick it up via the FastAPI app handle. The
  factory accepts an injected store, which the test-suite uses to
  point the dashboard at a temporary scans directory.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agent_guardian._version import __version__
from agent_guardian.server.scan_store import ScanStore

__all__ = ["create_app"]

_LOG = logging.getLogger(__name__)

_SERVER_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _SERVER_DIR / "static"
_TEMPLATE_DIR = _SERVER_DIR / "templates"


def _cors_allow_origins() -> list[str]:
    """Resolve the CORS allow-list (restrictive by default).

    The dashboard is a same-origin server-rendered app -- no browser JS calls
    it cross-origin -- so the default allow-list is empty (no cross-origin
    reads). An operator who fronts it from a different origin can opt in via
    ``AGENT_GUARDIAN_DASHBOARD_CORS_ORIGINS`` (comma-separated). We never emit a
    wildcard ``*`` automatically.
    """
    raw = os.environ.get("AGENT_GUARDIAN_DASHBOARD_CORS_ORIGINS", "").strip()
    if not raw:
        return []
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app(*, scan_store: ScanStore | None = None) -> FastAPI:
    """Build the FastAPI dashboard app.

    Args:
        scan_store: Optional pre-built :class:`ScanStore`. The factory
            accepts injection so tests can point the dashboard at a
            scratch directory.
    """
    app = FastAPI(
        title="AgentGuardian",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Restrictive CORS. Default = no cross-origin access (the dashboard is a
    # same-origin server-rendered app). Operators front-ending it from another
    # origin opt in via AGENT_GUARDIAN_DASHBOARD_CORS_ORIGINS; we never auto-
    # emit a wildcard.
    allow_origins = _cors_allow_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    if allow_origins:
        _LOG.info("dashboard CORS allow-list: %s", ", ".join(allow_origins))

    # Templates -- exposed both on app.state for handlers and stamped
    # with two globals every page expects.
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    templates.env.globals["version"] = __version__
    app.state.templates = templates

    # Static mount. The directory always exists in the wheel -- we
    # create it eagerly in dev to keep mypy / type-checkers happy.
    _STATIC_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Scan store -- either injected for tests or default-ed.
    app.state.scan_store = scan_store if scan_store is not None else ScanStore()

    # Routes -- import here so the factory is the single entry point.
    from agent_guardian.server.routes import (
        about,
        aivss,
        analytics,
        coverage,
        events,
        export,
        findings,
        home,
        scan,
        swarm,
        transcripts,
    )

    app.include_router(home.router)
    app.include_router(scan.router)
    app.include_router(findings.router)
    app.include_router(aivss.router)
    app.include_router(swarm.router)
    app.include_router(transcripts.router)
    app.include_router(export.router)
    app.include_router(about.router)
    app.include_router(events.router)
    app.include_router(coverage.router)
    app.include_router(analytics.router)

    return app
