"""Azure OpenAI Service client (PRD §14.3).

Azure OpenAI speaks the OpenAI Chat Completions wire format, so the heavy
lifting is inherited from :class:`OpenAICompatClient`. Two things differ and
are overridden here:

1. **URL shape (reviewer correction #2).** The standard, generally-available
   Azure path is the *deployment* path with a mandatory ``api-version`` query
   parameter::

       {endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}

   The deployment name IS the ``model_id`` from the spec — Azure routes by the
   deployment you named in the portal, not the base model id. The ``/openai/v1``
   compatibility path is a region-restricted opt-in preview and is deliberately
   NOT the default (it 404s on the vast majority of real deployments).

2. **Auth header.** The default mode uses ``api-key: <key>`` (NOT
   ``Authorization: Bearer``). Optional Microsoft Entra ID (keyless) auth is
   gated behind ``AZURE_USE_ENTRA=1`` and the ``[azure]`` extra
   (``azure-identity``), with a lazy import guard that mirrors
   :mod:`agent_guardian.llm.bedrock`'s botocore guard. In Entra mode the header
   becomes ``Authorization: Bearer <token>``.

No vendor SDK type leaks out of this module: ``azure-identity`` is used solely
to mint a bearer token; everything on the wire is raw httpx.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from agent_guardian.llm.errors import LLMAuthError
from agent_guardian.llm.openai_compat import OpenAICompatClient

__all__ = ["AzureOpenAIClient"]

_LOG = logging.getLogger(__name__)

# Current GA api-version for the standard deployment path. A GA (non-preview)
# default is required so the client works against deployments that reject
# preview api-versions. Overridable via the ``AZURE_OPENAI_API_VERSION`` env var
# or the ``+api_version=`` spec qualifier (set one of those to opt into a newer
# preview api-version when you need preview-only features).
_DEFAULT_API_VERSION = "2024-10-21"

# Default Entra token scope. The legacy ``cognitiveservices`` scope works for
# both the classic and v1 surfaces; users on the newer Foundry scope can set
# ``AZURE_OPENAI_SCOPE=https://ai.azure.com/.default``.
_DEFAULT_ENTRA_SCOPE = "https://cognitiveservices.azure.com/.default"

# Refresh the Entra token this many seconds before its stated expiry so a
# long-running scan never sends an about-to-expire token.
_ENTRA_REFRESH_SKEW_S = 300.0

# azure-identity is an optional dependency (``[azure]`` extra) used ONLY to mint
# an Entra bearer token for keyless auth. Imported lazily — the default api-key
# path (and the whole module) works without it. Pattern mirrors bedrock.py's
# botocore guard.
_AZURE_IDENTITY_IMPORT_ERROR: Exception | None
try:  # pragma: no cover — import guard
    from azure.identity import DefaultAzureCredential

    _AZURE_IDENTITY_AVAILABLE = True
    _AZURE_IDENTITY_IMPORT_ERROR = None
except ImportError as _exc:  # pragma: no cover — import guard
    _AZURE_IDENTITY_AVAILABLE = False
    _AZURE_IDENTITY_IMPORT_ERROR = _exc
    _LOG.debug("azure: azure-identity not installed (install via [azure] extra): %s", _exc)


class AzureOpenAIClient(OpenAICompatClient):
    """Azure OpenAI Service provider client.

    The ``model`` passed at request time is the Azure *deployment name* and is
    encoded into the URL path, so the constructor pins it as ``deployment``.
    """

    provider = "azure"
    default_max_concurrency = 10

    def __init__(
        self,
        *,
        deployment: str,
        endpoint: str | None = None,
        api_key: str | None = None,
        api_version: str | None = None,
        use_entra: bool | None = None,
        entra_scope: str | None = None,
        **kwargs: Any,
    ) -> None:
        resolved_endpoint = endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT")
        if not resolved_endpoint:
            raise LLMAuthError(
                "azure: AZURE_OPENAI_ENDPOINT is required (or pass +endpoint= in "
                "the model spec). Example: "
                "https://my-resource.openai.azure.com"
            )
        self.endpoint = resolved_endpoint.rstrip("/")
        self.deployment = deployment
        self.api_version = (
            api_version or os.environ.get("AZURE_OPENAI_API_VERSION") or _DEFAULT_API_VERSION
        )
        self._use_entra = (
            use_entra if use_entra is not None else os.environ.get("AZURE_USE_ENTRA") == "1"
        )
        self._entra_scope = (
            entra_scope or os.environ.get("AZURE_OPENAI_SCOPE") or _DEFAULT_ENTRA_SCOPE
        )
        self._entra_token: str | None = None
        self._entra_expires_on: float = 0.0
        self._entra_lock = asyncio.Lock()
        self._entra_credential: Any | None = None

        if self._use_entra:
            if not _AZURE_IDENTITY_AVAILABLE:
                raise LLMAuthError(
                    "azure: Entra ID auth requested (AZURE_USE_ENTRA=1) but "
                    "azure-identity is not installed. Install the Azure extra: "
                    "'pip install agent-guardian[azure]' or 'uv sync --extra azure'. "
                    f"(import error: {_AZURE_IDENTITY_IMPORT_ERROR})"
                )
            self._entra_credential = DefaultAzureCredential()
        elif not api_key:
            raise LLMAuthError(
                "azure: no API key found. Set AGENT_GUARDIAN_AZURE_API_KEY or "
                "AZURE_OPENAI_API_KEY, or enable Entra auth with AZURE_USE_ENTRA=1 "
                "(requires the [azure] extra)."
            )

        # ``base_url`` on BaseLLM is the endpoint; the deployment + api-version
        # are folded into ``_request_url`` below.
        super().__init__(
            provider="azure",
            base_url=self.endpoint,
            api_key=api_key,
            **kwargs,
        )

    def _request_url(self) -> str:
        # Reviewer correction #2 — STANDARD deployment path with api-version.
        return (
            f"{self.endpoint}/openai/deployments/{self.deployment}"
            f"/chat/completions?api-version={self.api_version}"
        )

    def _token_is_fresh(self) -> bool:
        return self._entra_token is not None and time.time() < (
            self._entra_expires_on - _ENTRA_REFRESH_SKEW_S
        )

    async def _ensure_entra_token(self) -> None:
        """Refresh + cache the Entra bearer token without blocking the loop.

        ``DefaultAzureCredential.get_token`` is synchronous network I/O (it may
        hit IMDS / the Azure CLI / a token endpoint), so it is offloaded to a
        worker thread. A double-checked :class:`asyncio.Lock` ensures only one
        coroutine mints at a time — the rest await the lock and observe the
        freshly cached token. Re-minted ``_ENTRA_REFRESH_SKEW_S`` seconds before
        the stated expiry so a long scan never sends an about-to-expire token.
        """
        if self._token_is_fresh():
            return
        async with self._entra_lock:
            if self._token_is_fresh():  # another coroutine refreshed while we waited
                return
            assert self._entra_credential is not None  # guaranteed by __init__
            try:
                token = await asyncio.to_thread(self._entra_credential.get_token, self._entra_scope)
            except Exception as exc:  # normalise to our error hierarchy
                raise LLMAuthError(f"azure: Entra token acquisition failed: {exc}") from exc
            self._entra_token = str(token.token)
            self._entra_expires_on = float(token.expires_on)

    async def _prepare_request(self) -> None:
        # Mint the Entra token off-thread before the synchronous _headers() runs
        # (the api-key path is a no-op).
        if self._use_entra:
            await self._ensure_entra_token()

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        headers.update(self._extra_headers)
        if self._use_entra:
            # Token is minted by ``_prepare_request`` (called from _send) so this
            # stays pure/synchronous and never blocks the loop.
            if self._entra_token is None:  # pragma: no cover — defensive
                raise LLMAuthError(
                    "azure: Entra token not available (internal: _prepare_request "
                    "must run before _headers)"
                )
            headers["authorization"] = f"Bearer {self._entra_token}"
        elif self.api_key:
            # Azure's api-key header — NOT ``Authorization: Bearer``.
            headers["api-key"] = self.api_key
        return headers
