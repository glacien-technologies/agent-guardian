"""OAuth2 client-credentials auth (Stage 1A).

Fetches an access token from a token endpoint using the ``client_credentials``
grant, caches it in memory keyed by ``client_id + scope``, and refreshes it
shortly before expiry. On a 401 it force-refreshes and signals the caller to
retry the request exactly once.

The token fetch uses an **injected** :class:`httpx.AsyncClient` (the transport
shares its own client). Secrets (``client_id`` / ``client_secret``) are
pre-resolved strings supplied at construction.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import ClassVar

import httpx

from agent_guardian.llm.errors import LLMAuthError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider

__all__ = ["CachedToken", "OAuth2ClientCredentialsAuth"]

_LOG = logging.getLogger(__name__)


class CachedToken:
    """An in-memory access token with its computed expiry deadline."""

    __slots__ = ("access_token", "expires_at")

    def __init__(self, access_token: str, expires_at: float) -> None:
        self.access_token = access_token
        self.expires_at = expires_at

    def is_fresh(self, *, now: float, leeway: float) -> bool:
        """True when the token is still valid with ``leeway`` seconds to spare."""
        return now < (self.expires_at - leeway)


class OAuth2ClientCredentialsAuth(AuthProvider):
    """OAuth2 ``client_credentials`` provider with an in-memory token cache."""

    # Process-wide cache so multiple transports sharing the same client_id+scope
    # reuse one token. Keyed by ``f"{client_id}\x00{scope}"``.
    _cache: ClassVar[dict[str, CachedToken]] = {}

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str = "",
        client: httpx.AsyncClient,
        expiry_leeway_seconds: float = 60.0,
    ) -> None:
        if not token_url:
            raise ValueError("OAuth2ClientCredentialsAuth requires a token_url")
        if not client_id:
            raise ValueError("OAuth2ClientCredentialsAuth requires a client_id")
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._client = client
        self._leeway = expiry_leeway_seconds
        self._lock = asyncio.Lock()

    @property
    def _cache_key(self) -> str:
        return f"{self._client_id}\x00{self._scope}"

    async def apply(self, ctx: AuthContext) -> None:
        token = await self._get_token(force=False)
        ctx.headers["Authorization"] = f"Bearer {token}"

    async def on_unauthorized(self, ctx: AuthContext) -> bool:
        """Force-refresh the token and re-stamp the header; retry once."""
        token = await self._get_token(force=True)
        ctx.headers["Authorization"] = f"Bearer {token}"
        return True

    async def _get_token(self, *, force: bool) -> str:
        async with self._lock:
            now = time.monotonic()
            if not force:
                cached = self._cache.get(self._cache_key)
                if cached is not None and cached.is_fresh(now=now, leeway=self._leeway):
                    return cached.access_token
            cached = await self._fetch_token()
            self._cache[self._cache_key] = cached
            return cached.access_token

    async def _fetch_token(self) -> CachedToken:
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            data["scope"] = self._scope
        try:
            resp = await self._client.post(self._token_url, data=data)
        except httpx.HTTPError as exc:
            _LOG.debug("oauth2: token request transport error (%s)", exc)
            raise LLMAuthError(f"oauth2: token request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise LLMAuthError(
                f"oauth2: token endpoint returned {resp.status_code}: {resp.text[:256]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise LLMAuthError(f"oauth2: token response was not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise LLMAuthError("oauth2: token response was not a JSON object")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise LLMAuthError("oauth2: token response missing 'access_token'")
        expires_in = payload.get("expires_in", 3600)
        try:
            expires_in_f = float(expires_in)
        except (TypeError, ValueError):
            _LOG.debug("oauth2: non-numeric expires_in %r, defaulting to 3600s", expires_in)
            expires_in_f = 3600.0
        return CachedToken(access_token, time.monotonic() + expires_in_f)

    @classmethod
    def clear_cache(cls) -> None:
        """Drop all cached tokens (test helper)."""
        cls._cache.clear()
