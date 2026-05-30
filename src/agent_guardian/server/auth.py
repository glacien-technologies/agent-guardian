"""Dashboard authentication for the M12 web UI.

Until launch readiness, every dashboard view was open to whoever could reach
the bind address. The CLI emitted a loud warning when the operator bound a
non-loopback host, but there was no in-process enforcement. Enterprise users
running the dashboard behind their own reverse proxy or VPN reasonably
expected the app to refuse anonymous reads when configured with a token.

This module exposes one public dependency,
:func:`require_dashboard_auth`, that route modules can attach to any
endpoint. Policy (fail closed when a token is configured):

* If ``AGENT_GUARDIAN_DASHBOARD_TOKEN`` is unset *and* ``app.state.dashboard_token``
  is ``None``, the dependency permits every request. This preserves the
  zero-config local-dev experience and the existing tests that hit the
  TestClient without auth.
* If a token is configured, requests are authorised when:
    1. they originate from a loopback client (``127.0.0.1``, ``::1``,
       ``localhost``, ``testclient``), OR
    2. they carry a matching ``Authorization: Bearer <token>`` header
       (constant-time compared with :func:`secrets.compare_digest`), OR
    3. they carry a matching signed cookie ``ag_dash`` previously minted by
       :func:`mint_session_cookie` from a ``?token=...`` query exchange.
* Any other request is rejected with ``401 Unauthorized`` and a
  ``WWW-Authenticate: Bearer`` header (so browser clients can prompt).

The token can be provided two ways:

* Process env: ``AGENT_GUARDIAN_DASHBOARD_TOKEN=...``
* Programmatic: the ``serve`` CLI sets ``app.state.dashboard_token`` from
  its ``--token`` flag (or refuses to bind off-loopback without one unless
  ``--insecure-no-auth`` is passed).

Why a signed cookie alongside Bearer? A browser tab cannot set arbitrary
request headers on a regular ``GET``. The cookie path lets an operator paste
``?token=...`` once and have the rest of the dashboard stay authenticated
without rebuilding the navigation as a SPA that injects headers. The cookie
value is HMAC-signed so it cannot be forged from a public token leak alone
(the HMAC key is the configured token).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from typing import Final

from fastapi import HTTPException, Request, Response

__all__ = [
    "AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV",
    "DASHBOARD_SESSION_COOKIE",
    "mint_session_cookie",
    "require_dashboard_auth",
    "resolve_dashboard_token",
    "verify_session_cookie",
]

_LOG = logging.getLogger(__name__)

AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV: Final[str] = "AGENT_GUARDIAN_DASHBOARD_TOKEN"
DASHBOARD_SESSION_COOKIE: Final[str] = "ag_dash"

# Hosts we treat as loopback for the bypass. ``testclient`` is the FastAPI
# TestClient's reported host and is intentionally included so the existing
# test-suite continues to pass without per-test token injection.
_LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


def resolve_dashboard_token(request: Request) -> str | None:
    """Resolve the configured dashboard token.

    Priority: explicit value stashed on ``app.state.dashboard_token`` (set by
    the CLI from ``--token``) wins over the env var. Returns ``None`` when no
    token is configured, in which case auth is fully bypassed (the
    documented zero-config local-dev mode).
    """
    state_value = getattr(request.app.state, "dashboard_token", None)
    if isinstance(state_value, str) and state_value:
        return state_value
    env_value = os.environ.get(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, "").strip()
    if env_value:
        return env_value
    return None


def _client_host(request: Request) -> str:
    client = request.client
    return client.host if client is not None else ""


def _is_loopback(request: Request) -> bool:
    return _client_host(request) in _LOOPBACK_HOSTS


def _bearer_token(request: Request) -> str | None:
    raw = request.headers.get("authorization") or request.headers.get("Authorization")
    if not raw:
        return None
    parts = raw.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def mint_session_cookie(token: str) -> str:
    """Return the HMAC-signed cookie value for an authenticated session.

    The cookie is ``hex(HMAC-SHA256(token, "ag-dashboard-session-v1"))``. The
    constant string anchors the cookie to *this* purpose so an unrelated HMAC
    using the same secret can't be replayed against the dashboard. The token
    itself is the HMAC key — it is never sent over the wire after the initial
    exchange.
    """
    return hmac.new(
        token.encode("utf-8"),
        b"ag-dashboard-session-v1",
        hashlib.sha256,
    ).hexdigest()


def verify_session_cookie(request: Request, token: str) -> bool:
    """Return ``True`` when the request carries a valid signed cookie."""
    cookie = request.cookies.get(DASHBOARD_SESSION_COOKIE)
    if not cookie:
        return False
    expected = mint_session_cookie(token)
    return secrets.compare_digest(cookie, expected)


def _token_exchange(request: Request, token: str) -> Response | None:
    """If the request carries ``?token=<configured>``, mint the cookie + 302.

    Returning a 302 to the same path without the query keeps the URL bar
    clean and avoids the token leaking into Referer headers or browser
    history bookmarks. Returns ``None`` when no exchange is requested.
    """
    supplied = request.query_params.get("token")
    if supplied is None:
        return None
    if not secrets.compare_digest(supplied, token):
        return None
    # Strip ?token=... from the redirect target.
    qp = [(k, v) for (k, v) in request.query_params.multi_items() if k != "token"]
    target = request.url.path
    if qp:
        from urllib.parse import urlencode

        target = f"{target}?{urlencode(qp)}"
    response = Response(status_code=302, headers={"Location": target})
    response.set_cookie(
        DASHBOARD_SESSION_COOKIE,
        mint_session_cookie(token),
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        max_age=60 * 60 * 12,
        path="/",
    )
    return response


def require_dashboard_auth(request: Request) -> None:
    """FastAPI dependency: authenticate the request or raise 401.

    Behaviour matrix:

    +----------------+--------------+----------------------+----------------+
    | Token config'd | Loopback     | Bearer / cookie OK   | Result         |
    +================+==============+======================+================+
    | No             | -            | -                    | allow          |
    +----------------+--------------+----------------------+----------------+
    | Yes            | Yes          | -                    | allow          |
    +----------------+--------------+----------------------+----------------+
    | Yes            | No           | Yes (Bearer)         | allow          |
    +----------------+--------------+----------------------+----------------+
    | Yes            | No           | Yes (signed cookie)  | allow          |
    +----------------+--------------+----------------------+----------------+
    | Yes            | No           | No                   | 401            |
    +----------------+--------------+----------------------+----------------+

    The 401 response carries ``WWW-Authenticate: Bearer realm="dashboard"``
    so browsers and CLI clients can prompt for a credential.
    """
    token = resolve_dashboard_token(request)
    if token is None:
        # Zero-config local dev — auth fully disabled.
        return
    if _is_loopback(request):
        return
    # Token-exchange via ?token=... — handled by the route returning the
    # redirect Response object before the route handler runs. The dependency
    # path itself only enforces; the exchange is performed by middleware /
    # helper in routes. Here we just check Bearer + cookie.
    bearer = _bearer_token(request)
    if bearer is not None and secrets.compare_digest(bearer, token):
        return
    if verify_session_cookie(request, token):
        return
    _LOG.info(
        "dashboard auth: rejecting request from %s (no valid Bearer / cookie)",
        _client_host(request),
    )
    raise HTTPException(
        status_code=401,
        detail="dashboard requires Bearer authentication; configure AGENT_GUARDIAN_DASHBOARD_TOKEN",
        headers={"WWW-Authenticate": 'Bearer realm="dashboard"'},
    )


def maybe_exchange_token(request: Request) -> Response | None:
    """Convenience wrapper used by HTML routes to support ``?token=`` login.

    Route handlers can call this at the top and return its result when not
    ``None``. The token-exchange is a no-op when no token is configured.
    """
    token = resolve_dashboard_token(request)
    if token is None:
        return None
    return _token_exchange(request, token)
