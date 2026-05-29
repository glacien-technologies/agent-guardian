"""MCP OAuth 2.1 + PKCE (S256) auth provider with RFC 9728 discovery (Stage 3).

Implements the Model Context Protocol authorization spec for HTTP transports:

* **PKCE (S256).** A high-entropy ``code_verifier`` is generated with
  :mod:`secrets`; the ``code_challenge`` is ``base64url(sha256(verifier))`` with
  the padding stripped and ``code_challenge_method=S256``. See
  :func:`compute_pkce`.
* **RFC 9728 discovery.** When no ``token_url`` is supplied the provider walks
  ``{resource}/.well-known/oauth-protected-resource`` to find the first
  ``authorization_servers[]`` entry, then ``{auth_server}/.well-known/
  oauth-authorization-server`` to read its ``token_endpoint`` (and
  ``authorization_endpoint``). The discovered endpoints are cached on the
  instance.
* **Token acquisition.** The primary automated-scan path is the
  ``client_credentials`` grant (M2M). The provider also carries the PKCE
  challenge for any authorization-code exchange. Tokens are cached in memory
  and refreshed shortly before expiry; :meth:`on_unauthorized` force-refreshes
  and signals a single retry.

Bearer tokens are written **only** to the ``Authorization`` request header — the
provider never appends the token to a query string (this is asserted in
:meth:`apply`).

The token fetch uses an **injected** :class:`httpx.AsyncClient` (the transport
shares its own client). This module is a plain ``httpx`` + stdlib implementation
and does not depend on any ``mcp`` package being installed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import secrets
import time
from typing import ClassVar, NamedTuple
from urllib.parse import urlsplit, urlunsplit

import httpx

from agent_guardian.llm.errors import LLMAuthError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider

__all__ = [
    "DiscoveredEndpoints",
    "McpCachedToken",
    "McpOAuthProvider",
    "PkcePair",
    "compute_pkce",
]

_LOG = logging.getLogger(__name__)

# RFC 9728 / OAuth 2.0 Authorization Server Metadata well-known suffixes.
_PROTECTED_RESOURCE_SUFFIX = "/.well-known/oauth-protected-resource"
_AUTH_SERVER_SUFFIX = "/.well-known/oauth-authorization-server"


class PkcePair(NamedTuple):
    """A PKCE ``code_verifier`` and its derived S256 ``code_challenge``."""

    verifier: str
    challenge: str


def compute_pkce(*, verifier: str | None = None) -> PkcePair:
    """Compute a PKCE S256 verifier/challenge pair.

    ``code_challenge = base64url(sha256(code_verifier))`` with the base64
    padding (``=``) stripped, per RFC 7636 §4.2. When ``verifier`` is omitted a
    fresh high-entropy verifier is generated with :mod:`secrets`.
    """
    if verifier is None:
        # 32 random bytes -> 43-char base64url string (within the RFC 7636
        # 43..128 length window).
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PkcePair(verifier=verifier, challenge=challenge)


class DiscoveredEndpoints(NamedTuple):
    """OAuth endpoints resolved via RFC 9728 protected-resource discovery."""

    token_endpoint: str
    authorization_endpoint: str | None


class McpCachedToken:
    """An in-memory MCP access token with its computed expiry deadline."""

    __slots__ = ("access_token", "expires_at")

    def __init__(self, access_token: str, expires_at: float) -> None:
        self.access_token = access_token
        self.expires_at = expires_at

    def is_fresh(self, *, now: float, leeway: float) -> bool:
        """True when the token is still valid with ``leeway`` seconds to spare."""
        return now < (self.expires_at - leeway)


class McpOAuthProvider(AuthProvider):
    """MCP OAuth 2.1 + PKCE (S256) provider with RFC 9728 discovery."""

    # Process-wide token cache so transports sharing the same identity reuse one
    # token. Keyed by ``f"{client_id}\x00{scope}\x00{resource}"``.
    _cache: ClassVar[dict[str, McpCachedToken]] = {}

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str | None = None,
        scopes: list[str],
        resource: str | None,
        token_url: str | None,
        client: httpx.AsyncClient,
        authorization_endpoint: str | None = None,
        expiry_leeway_seconds: float = 60.0,
    ) -> None:
        if not client_id:
            raise ValueError("McpOAuthProvider requires a client_id")
        if token_url is None and resource is None:
            raise ValueError(
                "McpOAuthProvider requires either a token_url or a resource to discover from"
            )
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes = list(scopes)
        self._resource = resource
        self._token_url = token_url
        self._client = client
        self._leeway = expiry_leeway_seconds
        # PKCE material is generated once per provider instance and carried into
        # any authorization-code exchange.
        self._pkce = compute_pkce()
        self._authorization_endpoint = authorization_endpoint
        self._discovered: DiscoveredEndpoints | None = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # PKCE accessors
    # ------------------------------------------------------------------ #

    @property
    def code_verifier(self) -> str:
        """The PKCE ``code_verifier`` for this provider instance."""
        return self._pkce.verifier

    @property
    def code_challenge(self) -> str:
        """The PKCE S256 ``code_challenge`` for this provider instance."""
        return self._pkce.challenge

    @property
    def code_challenge_method(self) -> str:
        """The PKCE challenge method (always ``S256`` per the MCP spec)."""
        return "S256"

    @property
    def scope(self) -> str:
        """Space-delimited scope string for token requests."""
        return " ".join(self._scopes)

    @property
    def _cache_key(self) -> str:
        return f"{self._client_id}\x00{self.scope}\x00{self._resource or ''}"

    # ------------------------------------------------------------------ #
    # AuthProvider interface
    # ------------------------------------------------------------------ #

    @staticmethod
    def _assert_no_token_in_query(ctx: AuthContext) -> None:
        # Bearer tokens MUST travel in the Authorization header and NEVER in a
        # query string (MCP authorization spec). Guard against the URL already
        # carrying the token and never mutate ctx.url ourselves.
        assert "access_token=" not in ctx.url, "bearer token must never appear in a query string"

    async def apply(self, ctx: AuthContext) -> None:
        self._assert_no_token_in_query(ctx)
        token = await self._get_token(force=False)
        ctx.headers["Authorization"] = f"Bearer {token}"

    async def on_unauthorized(self, ctx: AuthContext) -> bool:
        """Force-refresh the token and re-stamp the header; retry once."""
        self._assert_no_token_in_query(ctx)
        token = await self._get_token(force=True)
        ctx.headers["Authorization"] = f"Bearer {token}"
        return True

    # ------------------------------------------------------------------ #
    # Token acquisition
    # ------------------------------------------------------------------ #

    async def _get_token(self, *, force: bool) -> str:
        async with self._lock:
            now = time.monotonic()
            if not force:
                cached = self._cache.get(self._cache_key)
                if cached is not None and cached.is_fresh(now=now, leeway=self._leeway):
                    return cached.access_token
            token_endpoint = await self._resolve_token_endpoint()
            cached = await self._fetch_token(token_endpoint)
            self._cache[self._cache_key] = cached
            return cached.access_token

    async def _resolve_token_endpoint(self) -> str:
        """Return the token endpoint, running RFC 9728 discovery if needed."""
        if self._token_url is not None:
            return self._token_url
        if self._discovered is None:
            self._discovered = await self._discover()
            if self._authorization_endpoint is None:
                self._authorization_endpoint = self._discovered.authorization_endpoint
        return self._discovered.token_endpoint

    async def _discover(self) -> DiscoveredEndpoints:
        """RFC 9728 discovery: protected-resource -> authorization-server."""
        if self._resource is None:  # pragma: no cover - guarded in __init__
            raise LLMAuthError("mcp_oauth: cannot discover endpoints without a resource")
        prm_url = self._well_known(self._resource, _PROTECTED_RESOURCE_SUFFIX)
        prm = await self._get_json(prm_url, what="protected-resource metadata")
        servers = prm.get("authorization_servers")
        if not isinstance(servers, list) or not servers:
            raise LLMAuthError(
                "mcp_oauth: protected-resource metadata missing 'authorization_servers'"
            )
        auth_server = servers[0]
        if not isinstance(auth_server, str) or not auth_server:
            raise LLMAuthError("mcp_oauth: 'authorization_servers[0]' was not a URL string")
        asm_url = self._well_known(auth_server, _AUTH_SERVER_SUFFIX)
        asm = await self._get_json(asm_url, what="authorization-server metadata")
        token_endpoint = asm.get("token_endpoint")
        if not isinstance(token_endpoint, str) or not token_endpoint:
            raise LLMAuthError("mcp_oauth: authorization-server metadata missing 'token_endpoint'")
        authz = asm.get("authorization_endpoint")
        authorization_endpoint = authz if isinstance(authz, str) and authz else None
        _LOG.debug("mcp_oauth: discovered token_endpoint=%s", token_endpoint)
        return DiscoveredEndpoints(
            token_endpoint=token_endpoint,
            authorization_endpoint=authorization_endpoint,
        )

    @staticmethod
    def _well_known(base: str, suffix: str) -> str:
        """Join a ``.well-known`` suffix onto ``base`` ignoring any path/query.

        Per RFC 8414 / RFC 9728 the well-known document lives at the origin.
        """
        parts = urlsplit(base)
        return urlunsplit((parts.scheme, parts.netloc, suffix, "", ""))

    async def _get_json(self, url: str, *, what: str) -> dict[str, object]:
        try:
            resp = await self._client.get(url)
        except httpx.HTTPError as exc:
            _LOG.debug("mcp_oauth: %s request transport error (%s)", what, exc)
            raise LLMAuthError(f"mcp_oauth: {what} request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise LLMAuthError(f"mcp_oauth: {what} returned {resp.status_code}: {resp.text[:256]}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise LLMAuthError(f"mcp_oauth: {what} was not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise LLMAuthError(f"mcp_oauth: {what} was not a JSON object")
        return payload

    async def _fetch_token(self, token_endpoint: str) -> McpCachedToken:
        # Client-credentials grant (M2M) is the primary automated-scan path. The
        # PKCE challenge is carried per spec for environments that bind it to the
        # token request; an authorization-code exchange would also include the
        # verifier here.
        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "code_challenge": self._pkce.challenge,
            "code_challenge_method": self.code_challenge_method,
        }
        if self._client_secret:
            data["client_secret"] = self._client_secret
        if self._scopes:
            data["scope"] = self.scope
        if self._resource:
            data["resource"] = self._resource
        try:
            resp = await self._client.post(token_endpoint, data=data)
        except httpx.HTTPError as exc:
            _LOG.debug("mcp_oauth: token request transport error (%s)", exc)
            raise LLMAuthError(f"mcp_oauth: token request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise LLMAuthError(
                f"mcp_oauth: token endpoint returned {resp.status_code}: {resp.text[:256]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise LLMAuthError(f"mcp_oauth: token response was not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise LLMAuthError("mcp_oauth: token response was not a JSON object")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise LLMAuthError("mcp_oauth: token response missing 'access_token'")
        expires_in = payload.get("expires_in", 3600)
        try:
            expires_in_f = float(expires_in)
        except (TypeError, ValueError):
            _LOG.debug("mcp_oauth: non-numeric expires_in %r, defaulting to 3600s", expires_in)
            expires_in_f = 3600.0
        return McpCachedToken(access_token, time.monotonic() + expires_in_f)

    @classmethod
    def clear_cache(cls) -> None:
        """Drop all cached tokens (test helper)."""
        cls._cache.clear()
