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
from typing import Any

__all__ = [
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


async def _endpoint_reachability_preflight(
    endpoint: str,
    *,
    sample_body: dict[str, Any] | None = None,
) -> bool:
    """Probe ``endpoint`` twice with a short timeout. Return True iff reachable.

    Used before an ``--endpoint`` scan so an unreachable target fails fast with
    ``EXIT_TARGET_UNREACHABLE`` instead of spending the LLM budget on
    every-probe timeouts.

    Body selection (in order of preference):

    1. ``sample_body`` if supplied — used verbatim. Intended for the
       contract-driven path which knows the on-wire shape.
    2. Otherwise a minimal ``{"input": "ping"}`` JSON body, which matches the
       de-facto convention most agent ``/chat`` endpoints accept. This avoids
       the spurious ``422 Unprocessable Entity`` that FastAPI returns when the
       endpoint declares a required body model and we POST an empty payload.

    Any HTTP response — including ``4xx`` (yes, even ``422``) — counts as
    "reachable". A schema-protected ``422`` proves the target is up and
    answering; it is an operator-config concern, not a transport fault.
    The only failure mode that marks the target down is a connect/timeout
    error across BOTH attempts. The timeout is generous (5s) to absorb Cloud
    Run cold starts.
    """
    import httpx

    # Cold-start-tolerant preflight: 3 attempts with progressive per-attempt
    # timeouts (5s, 10s, 15s; ≤30s total worst-case). Cloud Run / Lambda /
    # Knative often spin down after a few minutes idle; the first POST after
    # spin-down can take 6-12s for container boot + TLS handshake + first
    # response. A flat 5s x 2 (the previous code) routinely false-positived
    # UNREACHABLE against fully-healthy testbenches. Empirically attempt 1
    # succeeds for warm targets (~250ms); attempt 2 catches cold starts
    # (~5-10s); attempt 3 is the long-tail backstop.
    body: dict[str, Any] = sample_body if sample_body is not None else {"input": "ping"}
    per_attempt_timeouts = (5.0, 10.0, 15.0)
    last_exc: Exception | None = None
    for attempt, secs in enumerate(per_attempt_timeouts):
        async with httpx.AsyncClient(timeout=httpx.Timeout(secs)) as client:
            try:
                await client.post(endpoint, json=body)
                # Any HTTP response (200, 404, 422, 500, …) means the listener
                # is up. 422 from a schema-protected FastAPI endpoint is the
                # canonical "reachable, schema-protected" case — log it but do
                # NOT treat it as unreachable.
                if attempt > 0:
                    _LOG.info(
                        "endpoint preflight: %s reachable after %d attempt(s) "
                        "(target was likely cold-starting)",
                        endpoint,
                        attempt + 1,
                    )
                return True
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                last_exc = exc
                _LOG.debug(
                    "endpoint preflight: attempt %d/%d for %s failed (%s)",
                    attempt + 1,
                    len(per_attempt_timeouts),
                    endpoint,
                    exc,
                )
            except httpx.HTTPError as exc:
                # Any other transport error (PoolTimeout, RemoteProtocolError, etc.)
                # is treated as "reachable" -- we got far enough to be the
                # target's problem, not the network's.
                _LOG.debug(
                    "endpoint preflight: non-fatal HTTP error %s (%s) -- counted as reachable",
                    endpoint,
                    exc,
                )
                return True
    if last_exc is not None:
        _LOG.warning(
            "endpoint preflight: %s unreachable after %d attempts (last error: %s)",
            endpoint,
            len(per_attempt_timeouts),
            last_exc,
        )
    return False
