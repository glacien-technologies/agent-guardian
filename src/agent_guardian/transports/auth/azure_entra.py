"""Azure Entra ID (Azure AD) client-credentials auth (Stage 1B — cloud providers).

Fetches an access token from the Microsoft identity platform v2.0 token endpoint
(``https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token``) using the
``client_credentials`` grant, caches it in memory keyed by ``tenant + client_id
+ scope``, and refreshes it shortly before expiry. On a 401 it force-refreshes
and signals the caller to retry the request exactly once.

This mirrors the OAuth2 client-credentials provider (see
:mod:`agent_guardian.transports.auth.oauth2`) but pins the token endpoint to the
Entra tenant. The token fetch uses an **injected** :class:`httpx.AsyncClient`.
Secrets (``client_id`` / ``client_secret``) are pre-resolved strings supplied at
construction.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import ClassVar

import httpx

from agent_guardian.llm.errors import LLMAuthError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider

__all__ = ["AzureEntraAuth", "AzureEntraCachedToken"]

_LOG = logging.getLogger(__name__)

_AUTHORITY = "https://login.microsoftonline.com"


class AzureEntraCachedToken:
    """An in-memory Entra access token with its computed expiry deadline."""

    __slots__ = ("access_token", "expires_at")

    def __init__(self, access_token: str, expires_at: float) -> None:
        self.access_token = access_token
        self.expires_at = expires_at

    def is_fresh(self, *, now: float, leeway: float) -> bool:
        """True when the token is still valid with ``leeway`` seconds to spare."""
        return now < (self.expires_at - leeway)


class AzureEntraAuth(AuthProvider):
    """Azure Entra ID ``client_credentials`` provider with an in-memory cache."""

    # Process-wide cache so transports sharing the same tenant/client/scope reuse
    # one token. Keyed by ``f"{tenant_id}\x00{client_id}\x00{scope}"``.
    _cache: ClassVar[dict[str, AzureEntraCachedToken]] = {}

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str = "https://management.azure.com/.default",
        client: httpx.AsyncClient,
        authority: str = _AUTHORITY,
        expiry_leeway_seconds: float = 60.0,
    ) -> None:
        if not tenant_id:
            raise ValueError("AzureEntraAuth requires a tenant_id")
        if not client_id:
            raise ValueError("AzureEntraAuth requires a client_id")
        if not scope:
            raise ValueError("AzureEntraAuth requires a scope")
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._client = client
        self._token_url = f"{authority.rstrip('/')}/{tenant_id}/oauth2/v2.0/token"
        self._leeway = expiry_leeway_seconds
        self._lock = asyncio.Lock()

    @property
    def _cache_key(self) -> str:
        return f"{self._tenant_id}\x00{self._client_id}\x00{self._scope}"

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

    async def _fetch_token(self) -> AzureEntraCachedToken:
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": self._scope,
        }
        try:
            resp = await self._client.post(self._token_url, data=data)
        except httpx.HTTPError as exc:
            _LOG.debug("azure_entra: token request transport error (%s)", exc)
            raise LLMAuthError(f"azure_entra: token request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise LLMAuthError(
                f"azure_entra: token endpoint returned {resp.status_code}: {resp.text[:256]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise LLMAuthError(f"azure_entra: token response was not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise LLMAuthError("azure_entra: token response was not a JSON object")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise LLMAuthError("azure_entra: token response missing 'access_token'")
        expires_in = payload.get("expires_in", 3600)
        try:
            expires_in_f = float(expires_in)
        except (TypeError, ValueError):
            _LOG.debug("azure_entra: non-numeric expires_in %r, defaulting to 3600s", expires_in)
            expires_in_f = 3600.0
        return AzureEntraCachedToken(access_token, time.monotonic() + expires_in_f)

    async def aclose(self) -> None:
        """Close the injected httpx client used for the Entra token round-trip.

        Transports that own this provider call ``aclose`` here as part of their
        own teardown so the provider's data-plane client cannot leak. Calling
        ``aclose`` on an already-closed client is a no-op on httpx.
        """
        await self._client.aclose()

    @classmethod
    def clear_cache(cls) -> None:
        """Drop all cached tokens (test helper)."""
        cls._cache.clear()
