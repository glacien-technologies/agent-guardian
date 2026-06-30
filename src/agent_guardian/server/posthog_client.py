"""PostHog product-analytics client for the dashboard server.

Wraps the posthog Python SDK (instance-based Posthog() API) so the
dashboard can capture UI-side events (scan viewed, findings viewed,
export downloaded, etc.) tied to the anonymous install_id.

The client is a no-op when:
* ``POSTHOG_PROJECT_TOKEN`` is not set;
* ``AGENT_GUARDIAN_TELEMETRY`` is set to an opt-out value;
* the user has opted out via the CLI consent flow.

Usage::

    from agent_guardian.server.posthog_client import get_posthog
    ph = get_posthog(request.app)
    if ph:
        ph.capture(distinct_id, "scan_viewed", {"scan_id": scan_id})

``get_posthog`` returns the ``Posthog`` instance stored on
``app.state.posthog``, or ``None`` when telemetry is disabled /
the client was not initialised.  Callers must guard on ``None``
so a missing env var never raises.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI

__all__ = ["build_posthog_client", "get_posthog"]

_LOG = logging.getLogger(__name__)

_ENV_OFF_VALUES: frozenset[str] = frozenset({"off", "0", "false", "no"})


def _telemetry_env_opted_out() -> bool:
    raw = os.environ.get("AGENT_GUARDIAN_TELEMETRY")
    if raw is None:
        return False
    return raw.strip().lower() in _ENV_OFF_VALUES


def build_posthog_client() -> Any | None:
    """Construct and return a ``posthog.Posthog`` instance, or ``None``.

    Returns ``None`` when the env-var opt-out is active or the project
    token is not configured.  Callers should store the result on
    ``app.state.posthog`` and call :func:`get_posthog` to retrieve it.
    """
    if _telemetry_env_opted_out():
        _LOG.debug("posthog dashboard client: skipped (AGENT_GUARDIAN_TELEMETRY opt-out)")
        return None

    try:
        from agent_guardian.telemetry.consent import is_opted_in

        if not is_opted_in():
            _LOG.debug("posthog dashboard client: skipped (user opted out)")
            return None
    except Exception as exc:
        _LOG.debug("posthog dashboard client: consent check unavailable (%s) -- proceeding", exc)

    token = os.environ.get("POSTHOG_PROJECT_TOKEN", "").strip()
    if not token:
        _LOG.debug("posthog dashboard client: skipped (POSTHOG_PROJECT_TOKEN not set)")
        return None

    host = os.environ.get("POSTHOG_HOST", "https://us.i.posthog.com").strip()

    try:
        from posthog import Posthog

        client = Posthog(  # type: ignore[no-untyped-call, unused-ignore]  # untyped third-party SDK
            api_key=token,
            host=host,
            # MUST stay False: exception autocapture ships stack traces --
            # file paths, code context, and local variable values -- to
            # PostHog, which breaks the strict-anonymity guarantee (we never
            # send file paths, code, or finding content). Only the explicit,
            # curated capture() events in the routes are allowed out.
            enable_exception_autocapture=False,
        )
        _LOG.debug("posthog dashboard client: initialized (host=%s)", host)
        return client
    except Exception as exc:
        _LOG.warning(
            "posthog dashboard client: init failed (%s) — continuing without analytics", exc
        )
        return None


def get_posthog(app: FastAPI) -> Any | None:
    """Retrieve the ``Posthog`` instance from ``app.state``, or ``None``."""
    return getattr(app.state, "posthog", None)
