"""Shared endpoint reachability helpers for :mod:`agent_guardian.cli` and
:mod:`agent_guardian.preflight`.

Extracted to a leaf module so the CLI command runner (which is the contract
holder for endpoint preflighting) and the standalone preflight module can
both import these helpers without forming an import cycle.

History: these two helpers previously lived in ``agent_guardian.cli``;
``preflight`` lazily imported them inside the function body. CodeQL flagged
the arrangement as a cyclic import (``preflight`` -> ``cli`` -> ``preflight``).
Moving them here breaks the cycle structurally.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

__all__ = [
    "EndpointHealth",
    "_classify_endpoint_health",
    "_endpoint_reachability_preflight",
    "_is_placeholder_endpoint",
]

_LOG = logging.getLogger(__name__)

# Placeholder hosts we never preflight against (would fail by design).
_PLACEHOLDER_HOST_SUFFIXES: tuple[str, ...] = (".example.com", ".example.org", ".example.net")
_PLACEHOLDER_HOSTS: frozenset[str] = frozenset({"example.com", "example.org", "example.net"})


def _is_placeholder_endpoint(url: str) -> bool:
    """True iff ``url``'s host is a documentation/scaffold placeholder.

    Used by the endpoint preflight and the ``init --yes`` flow so a freshly
    scaffolded contract isn't pre-flighted against ``api.example.com``.
    """
    from urllib.parse import urlparse

    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:  # pragma: no cover -- defensive
        return False
    if not host:
        return False
    if host in _PLACEHOLDER_HOSTS:
        return True
    return any(host.endswith(suffix) for suffix in _PLACEHOLDER_HOST_SUFFIXES)


@dataclass(frozen=True)
class EndpointHealth:
    """Classified outcome of an endpoint preflight probe.

    ``classification`` is one of:

    * ``"healthy"``      — a 2xx response. The target answered correctly.
    * ``"auth_failed"``  — a 401/403. The listener is up but rejected our
      credentials/headers — an operator-config concern, NOT a box-down fault.
    * ``"client_error"`` — any other 4xx (404, 422, …). Reachable but the
      request shape/route is wrong from the target's point of view.
    * ``"server_error"`` — a 5xx. The listener is up but erroring internally.
    * ``"unreachable"``  — connect/timeout across all attempts (transport
      fault: DNS / TLS / listener down / never replied).

    ``reachable`` is True for every classification except ``"unreachable"`` —
    it preserves the legacy "got an HTTP response at all" semantics that the
    CLI's fast-fail gate depends on.
    """

    classification: str
    reachable: bool
    status_code: int | None = None
    detail: str = ""

    @property
    def healthy(self) -> bool:
        """True iff the target returned a 2xx response."""
        return self.classification == "healthy"


async def _classify_endpoint_health(
    endpoint: str,
    *,
    sample_body: dict[str, Any] | None = None,
) -> EndpointHealth:
    """Probe ``endpoint`` and classify the outcome (status-aware).

    Unlike a bare connectivity ping, this evaluates the HTTP status so callers
    can distinguish a healthy 2xx from an auth failure (401/403), a client
    error (4xx), a server error (5xx) or a transport-level unreachable target.

    Body selection (in order of preference):

    1. ``sample_body`` if supplied — used verbatim. Intended for the
       contract-driven path which knows the on-wire shape.
    2. Otherwise a minimal ``{"input": "ping"}`` JSON body, which matches the
       de-facto convention most agent ``/chat`` endpoints accept. This avoids
       the spurious ``422 Unprocessable Entity`` that FastAPI returns when the
       endpoint declares a required body model and we POST an empty payload.

    Retry/timeout behavior is unchanged from the legacy probe: 3 attempts with
    progressive per-attempt timeouts (5s, 10s, 15s; ≤30s total worst-case) to
    absorb Cloud Run / Lambda / Knative cold starts. Transport faults
    (connect/timeout) are retried; the FIRST HTTP response (any status) ends
    the loop and is classified — a 4xx/5xx is the target's answer, not a
    reason to keep retrying.
    """
    import httpx

    body: dict[str, Any] = sample_body if sample_body is not None else {"input": "ping"}
    per_attempt_timeouts = (5.0, 10.0, 15.0)
    last_exc: Exception | None = None
    for attempt, secs in enumerate(per_attempt_timeouts):
        async with httpx.AsyncClient(timeout=httpx.Timeout(secs)) as client:
            try:
                resp = await client.post(endpoint, json=body)
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                last_exc = exc
                _LOG.debug(
                    "endpoint preflight: attempt %d/%d for %s failed (%s)",
                    attempt + 1,
                    len(per_attempt_timeouts),
                    endpoint,
                    exc,
                )
                continue
            except httpx.HTTPError as exc:
                # Any other transport error (PoolTimeout, RemoteProtocolError, etc.)
                # is treated as "reachable" -- we got far enough to be the
                # target's problem, not the network's. We can't classify the
                # status, so report it as a client_error with the detail.
                _LOG.debug(
                    "endpoint preflight: non-fatal HTTP error %s (%s) -- counted as reachable",
                    endpoint,
                    exc,
                )
                return EndpointHealth(
                    classification="client_error",
                    reachable=True,
                    status_code=None,
                    detail=f"{type(exc).__name__}: {exc}",
                )

            # Got an HTTP response — the listener is up. Classify by status.
            if attempt > 0:
                _LOG.info(
                    "endpoint preflight: %s responded after %d attempt(s) "
                    "(target was likely cold-starting)",
                    endpoint,
                    attempt + 1,
                )
            status = resp.status_code
            if 200 <= status < 300:
                classification = "healthy"
            elif status in (401, 403):
                classification = "auth_failed"
            elif 400 <= status < 500:
                classification = "client_error"
            elif 500 <= status < 600:
                classification = "server_error"
            else:  # pragma: no cover -- 1xx/3xx are not expected from a POST probe
                classification = "client_error"
            return EndpointHealth(
                classification=classification,
                reachable=True,
                status_code=status,
                detail=f"HTTP {status}",
            )

    if last_exc is not None:
        _LOG.warning(
            "endpoint preflight: %s unreachable after %d attempts (last error: %s)",
            endpoint,
            len(per_attempt_timeouts),
            last_exc,
        )
    return EndpointHealth(
        classification="unreachable",
        reachable=False,
        status_code=None,
        detail=f"{type(last_exc).__name__}: {last_exc}" if last_exc is not None else "no response",
    )


async def _endpoint_reachability_preflight(
    endpoint: str,
    *,
    sample_body: dict[str, Any] | None = None,
) -> bool:
    """Probe ``endpoint`` and return True iff it is reachable (any HTTP response).

    Backward-compatible thin wrapper over :func:`_classify_endpoint_health`.
    The CLI's fast-fail gate (``EXIT_TARGET_UNREACHABLE``) only needs the
    boolean "did we get any HTTP response at all" signal; callers that want the
    status-aware classification (healthy vs auth_failed vs 4xx/5xx) should call
    :func:`_classify_endpoint_health` directly.

    Any HTTP response — including ``4xx`` (yes, even ``422``) — counts as
    "reachable". The only failure mode that marks the target down is a
    connect/timeout error across all attempts.
    """
    health = await _classify_endpoint_health(endpoint, sample_body=sample_body)
    return health.reachable
