"""Google Cloud auth providers (Stage 1B — cloud providers).

Two providers mint a Google OAuth2 bearer token and set
``Authorization: Bearer <token>``:

* :class:`GcpAdcAuth` — uses Application Default Credentials
  (:func:`google.auth.default`): env var ``GOOGLE_APPLICATION_CREDENTIALS``,
  ``gcloud`` user creds, or the GCE/GKE metadata server.
* :class:`GcpSaJsonAuth` — loads a service-account JSON string and mints a token
  via :class:`google.oauth2.service_account.Credentials`.

Both refresh the token shortly before expiry; on a 401 they force-refresh and
signal the caller to retry exactly once. ``google-auth`` is not a hard
dependency, so the import is guarded and a clear :class:`ImportError` with
remediation is raised at construction when it is missing.

Token refresh in ``google-auth`` is synchronous (it drives a ``requests``
transport), so it runs in a worker thread via :func:`asyncio.to_thread` to keep
the async contract.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any, cast

from agent_guardian.transports.auth.base import AuthContext, AuthProvider

if TYPE_CHECKING:
    from google.auth.credentials import Credentials

__all__ = ["GcpAdcAuth", "GcpSaJsonAuth"]

_LOG = logging.getLogger(__name__)

_GCP_HINT = "install google-auth to use Google Cloud authentication"
_DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def _build_request() -> Any:
    """Return a ``google.auth.transport.requests.Request`` (import-guarded)."""
    try:
        from google.auth.transport.requests import Request
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        _LOG.debug("gcp: google.auth.transport.requests import failed (%s)", exc)
        raise ImportError(f"Google Cloud auth requires google-auth: {_GCP_HINT}") from exc
    return Request()


class _GcpBearerBase(AuthProvider):
    """Shared bearer-token plumbing for GCP credential providers."""

    _credentials: Credentials

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

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
            creds = self._credentials
            if force or not creds.valid:
                await asyncio.to_thread(creds.refresh, _build_request())
            token = getattr(creds, "token", None)
            if not isinstance(token, str) or not token:
                raise ValueError(
                    f"{type(self).__name__}: credentials did not yield an access token"
                )
            return token


class GcpAdcAuth(_GcpBearerBase):
    """Bearer auth via Google Application Default Credentials."""

    def __init__(self, *, scopes: tuple[str, ...] = (_DEFAULT_SCOPE,)) -> None:
        super().__init__()
        try:
            import google.auth
        except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
            _LOG.debug("gcp: google.auth import failed (%s)", exc)
            raise ImportError(f"GcpAdcAuth requires google-auth: {_GCP_HINT}") from exc
        credentials, _project = google.auth.default(scopes=list(scopes))
        self._credentials = credentials


class GcpSaJsonAuth(_GcpBearerBase):
    """Bearer auth from a service-account JSON string."""

    def __init__(
        self,
        *,
        service_account_json: str,
        scopes: tuple[str, ...] = (_DEFAULT_SCOPE,),
    ) -> None:
        super().__init__()
        if not service_account_json:
            raise ValueError("GcpSaJsonAuth requires a service_account_json string")
        try:
            from google.oauth2 import service_account
        except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
            _LOG.debug("gcp: google.oauth2 import failed (%s)", exc)
            raise ImportError(f"GcpSaJsonAuth requires google-auth: {_GCP_HINT}") from exc
        try:
            info = json.loads(service_account_json)
        except ValueError as exc:
            raise ValueError(
                f"GcpSaJsonAuth: service_account_json is not valid JSON: {exc}"
            ) from exc
        if not isinstance(info, dict):
            raise ValueError("GcpSaJsonAuth: service_account_json must decode to a JSON object")
        self._credentials = cast(
            "Credentials",
            service_account.Credentials.from_service_account_info(info, scopes=list(scopes)),
        )
