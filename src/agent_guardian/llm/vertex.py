"""Google Vertex AI generative endpoints client (PRD §14.3).

The request-builder (:func:`build_vertex_payload`) and response-mapper
(:func:`map_vertex_response`) are pure functions — testable without auth.
:class:`VertexClient` wires them to the live ``generateContent`` endpoint using
an OAuth2 access token minted from Application Default Credentials (ADC).

``google-auth`` (the ``[gcp]`` extra) is imported lazily — only to mint and
refresh the bearer token. No google-auth type leaks onto the wire: the HTTP
call is raw httpx, identical in shape to the other providers. The lazy import
guard mirrors :mod:`agent_guardian.llm.bedrock`'s botocore guard.

Token refresh runs inside ``asyncio.to_thread`` (``creds.refresh`` is
synchronous I/O and would otherwise block the event loop) and is serialised by
an :class:`asyncio.Lock` so concurrent swarm agents sharing one client refresh
the token exactly once rather than stampeding the metadata server (reviewer
correction #4).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import with_backoff
from agent_guardian.logging_setup import log_model_request, log_model_response

__all__ = [
    "VERTEX_HOST_TEMPLATE",
    "VertexClient",
    "build_vertex_payload",
    "map_vertex_response",
]

_LOG = logging.getLogger(__name__)

VERTEX_HOST_TEMPLATE = "{region}-aiplatform.googleapis.com"

# The single OAuth2 scope ADC needs to call the Vertex AI surface.
_VERTEX_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# google-auth is an optional dependency (``[gcp]`` extra) used ONLY to resolve
# ADC + mint/refresh the OAuth2 bearer token. Imported lazily so the pure
# helpers (and the module itself, re-exported from ``agent_guardian.llm``) work
# without the extra installed. Pattern mirrors bedrock.py's botocore guard.
_GOOGLE_AUTH_IMPORT_ERROR: Exception | None
try:  # pragma: no cover — import guard
    import google.auth
    import google.auth.transport.requests

    _GOOGLE_AUTH_AVAILABLE = True
    _GOOGLE_AUTH_IMPORT_ERROR = None
except ImportError as _exc:  # pragma: no cover — import guard
    _GOOGLE_AUTH_AVAILABLE = False
    _GOOGLE_AUTH_IMPORT_ERROR = _exc
    _LOG.debug("vertex: google-auth not installed (install via [gcp] extra): %s", _exc)

_FINISH_REASON_MAP = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
    "OTHER": "stop",
}


def _role_to_vertex(role: str) -> str:
    """Vertex uses ``user`` / ``model`` rather than ``user`` / ``assistant``."""
    if role == "assistant":
        return "model"
    return role


def build_vertex_payload(request: LLMRequest) -> dict[str, Any]:
    """Convert an :class:`LLMRequest` into a Vertex ``generateContent`` body."""
    system_parts: list[str] = []
    contents: list[dict[str, Any]] = []
    for msg in request.messages:
        if msg.role == "system":
            system_parts.append(msg.content)
        else:
            contents.append({"role": _role_to_vertex(msg.role), "parts": [{"text": msg.content}]})

    generation_config: dict[str, Any] = {
        "maxOutputTokens": request.max_tokens,
        "temperature": request.temperature,
    }
    if request.stop is not None:
        generation_config["stopSequences"] = list(request.stop)

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": generation_config,
    }
    if system_parts:
        payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
    return payload


def map_vertex_response(model: str, data: dict[str, Any]) -> LLMResponse:
    """Map a Vertex ``generateContent`` response to :class:`LLMResponse`."""
    try:
        candidate = data["candidates"][0]
        parts = candidate.get("content", {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if "text" in p)
        raw_finish = candidate.get("finishReason", "STOP") or "STOP"
        usage = data.get("usageMetadata") or {}
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        _LOG.warning("vertex: malformed response (%s): %s", type(exc).__name__, exc)
        raise LLMResponseFormatError(f"vertex: malformed response: {exc}") from exc
    prompt_tokens = int(usage.get("promptTokenCount", 0))
    completion_tokens = int(usage.get("candidatesTokenCount", 0))
    total_tokens = int(usage.get("totalTokenCount", prompt_tokens + completion_tokens))
    return LLMResponse(
        text=text,
        model=model,
        provider="vertex",
        usage=LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        ),
        finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
        raw=data,
    )


class VertexClient(BaseLLM):
    """Google Vertex AI generative endpoints client.

    Authenticates via Application Default Credentials (ADC). ``project`` is
    required — resolved from the constructor, the ``+project=`` qualifier, or
    ``GOOGLE_CLOUD_PROJECT``. ``location`` defaults to ``us-central1``; the
    special value ``global`` uses the region-less ``aiplatform.googleapis.com``
    host with a ``locations/global`` path segment.
    """

    provider = "vertex"
    default_max_concurrency = 5

    def __init__(
        self,
        *,
        project: str = "",
        location: str = "us-central1",
        # Back-compat: the old constructor used ``region``. Accept it as an
        # alias so existing callers / tests keep working.
        region: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.project = project
        self.location = region or location
        # ``region`` retained as an alias attribute for back-compat with the
        # pre-M9 host()/tests.
        self.region = self.location
        self._token_refresh_lock = asyncio.Lock()
        self._access_token: str | None = None
        # ``Any`` (not ``Any | None``) so static checkers don't flag the
        # google-auth Credentials member access after the None-guard below; the
        # runtime ``is None`` check still drives lazy resolution.
        self._credentials: Any = None

    def host(self) -> str:
        if self.location == "global":
            return "aiplatform.googleapis.com"
        return VERTEX_HOST_TEMPLATE.format(region=self.location)

    def _resolve_credentials(self) -> Any:
        """Resolve ADC (blocking — reads key files / hits the metadata server).

        Called via ``asyncio.to_thread`` from inside the refresh lock so the
        one-time resolution neither blocks the event loop nor races across
        concurrent first calls.
        """
        creds, _detected_project = google.auth.default(scopes=[_VERTEX_SCOPE])
        return creds

    async def _get_access_token(self) -> str:
        """Return a valid OAuth2 access token, refreshing under a lock.

        Both first-call credential resolution AND token refresh happen under the
        same lock (reviewer correction #4) — so concurrent first calls neither
        double-resolve ADC nor stampede the refresh; the rest await the lock and
        observe the freshly-cached token. Both blocking calls (``google.auth.
        default`` and ``creds.refresh``) are offloaded to worker threads so the
        event loop is never blocked.
        """
        async with self._token_refresh_lock:
            creds = self._credentials
            if creds is None:
                creds = await asyncio.to_thread(self._resolve_credentials)
                self._credentials = creds
            if creds.expired or not creds.valid or creds.token is None:
                request = google.auth.transport.requests.Request()
                try:
                    await asyncio.to_thread(creds.refresh, request)
                except Exception as exc:  # normalise to our error hierarchy
                    raise LLMAuthError(
                        f"vertex: ADC token refresh failed: {exc}. Ensure "
                        "GOOGLE_APPLICATION_CREDENTIALS points at a valid "
                        "service-account key, or run "
                        "`gcloud auth application-default login`."
                    ) from exc
            token: str = str(creds.token)
            self._access_token = token
            return token

    def _request_url(self, model: str) -> str:
        return (
            f"https://{self.host()}/v1/projects/{self.project}"
            f"/locations/{self.location}/publishers/google/models/{model}:generateContent"
        )

    async def _send(self, request: LLMRequest) -> LLMResponse:
        if not _GOOGLE_AUTH_AVAILABLE:
            raise LLMAuthError(
                "vertex: google-auth is not installed. Install the GCP extra: "
                "'pip install agent-guardian[gcp]' or 'uv sync --extra gcp'. "
                f"(import error: {_GOOGLE_AUTH_IMPORT_ERROR})"
            )
        if not self.project:
            raise LLMAuthError(
                "vertex: project is required. Set GOOGLE_CLOUD_PROJECT or pass "
                "+project=<id> in the model spec (e.g. "
                "vertex:gemini-2.5-flash+project=my-proj)."
            )
        token = await self._get_access_token()
        url = self._request_url(request.model)
        payload = build_vertex_payload(request)
        log_model_request(
            _LOG,
            provider="vertex",
            model=request.model,
            n_messages=len(request.messages),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            seed=request.seed,
            request_body=payload,
            messages=request.messages,
        )
        headers = {
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
        }
        req = self._client.build_request("POST", url, json=payload, headers=headers)
        try:
            resp = await self._client.send(req)
        except httpx.TimeoutException as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTimeoutError(f"vertex: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTransientError(f"vertex: network error: {exc}") from exc
        _raise_for_vertex_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMResponseFormatError(f"vertex: invalid JSON: {exc}") from exc
        parsed = map_vertex_response(request.model, data)
        log_model_response(
            _LOG,
            response_text=parsed.text,
            usage=parsed.usage,
            finish_reason=parsed.finish_reason,
        )
        return parsed

    async def complete(self, request: LLMRequest) -> LLMResponse:
        async with self._semaphore:
            return await with_backoff(lambda: self._send(request))


def _raise_for_vertex_status(resp: httpx.Response) -> None:
    """Map a Vertex HTTP response to our error hierarchy."""
    if resp.status_code < 400:
        return
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"vertex: auth failed: {resp.status_code} {resp.text}")
    if resp.status_code == 429:
        retry_after_hdr = resp.headers.get("retry-after") or resp.headers.get("Retry-After")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "vertex: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("vertex 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("vertex: rate limited", retry_after=retry_after)
    if resp.status_code == 404:
        raise LLMPermanentError(f"vertex: model not found: {resp.status_code} {resp.text}")
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"vertex: transient {resp.status_code}: {resp.text}")
    raise LLMPermanentError(f"vertex: {resp.status_code} {resp.text}")
