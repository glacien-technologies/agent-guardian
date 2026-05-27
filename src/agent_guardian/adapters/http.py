"""HttpAdapter — Mode C: hosted HTTP API target (PRD §7).

Production transport for the six provider-shaped HTTP targets:

* ``openai`` — Chat Completions
* ``anthropic`` — Messages API
* ``bedrock`` — Converse API (NotImplementedError: SigV4 deferred)
* ``vertex`` — generateContent (NotImplementedError: OAuth2 deferred)
* ``agentcore`` — AgentCore Runtime ``POST /invocations`` (NotImplementedError: SigV4 deferred)
* ``generic`` — custom ``request_template`` + ``response_jsonpath``

The shape-specific request-build / response-extract logic lives in pure
functions under :mod:`agent_guardian.adapters.http_shapes`. This module owns
the transport: an :class:`httpx.AsyncClient`, retry/backoff using M3's
:func:`with_backoff`, and mapping of HTTP errors onto the LLM error
hierarchy (which we reuse for HTTP target errors since the failure modes —
auth, rate limit, timeout, transient, permanent — are semantically the
same).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.adapters.http_shapes.base import HttpShape, get_shape
from agent_guardian.adapters.http_shapes.generic_shape import (
    extract_response_text as generic_extract_response_text,
)
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import with_backoff

__all__ = ["HttpAdapter"]

_LOG = logging.getLogger(__name__)

# Shapes whose authentication scheme (SigV4 / OAuth2) is too heavyweight to
# implement in M9. The build_request / extract_response_text pure functions
# remain usable for unit tests, but ``HttpAdapter.call()`` refuses to send.
_AUTH_DEFERRED_SHAPES: frozenset[str] = frozenset({"bedrock", "vertex", "agentcore"})


class HttpAdapter(TargetAdapter):
    """Wraps a hosted HTTP/JSON API endpoint.

    Constructed with a shape name (``openai``, ``anthropic``, ``generic``,
    …), an endpoint URL, optional auth headers, and per-shape extras
    (``model`` for shapes that need it, ``request_template`` /
    ``response_jsonpath`` for the generic shape).

    ``call()`` is fully wired for ``openai``, ``anthropic``, and ``generic``.
    ``bedrock``, ``vertex``, and ``agentcore`` raise
    :class:`NotImplementedError` from ``call()`` — see ``M-future`` note in
    the docstring above — because SigV4 / OAuth2 helpers are out of scope
    for M9. The pure-function shapes continue to work for unit tests.
    """

    mode = "http"

    def __init__(
        self,
        endpoint: str,
        *,
        shape: str = "generic",
        auth_headers: dict[str, str] | None = None,
        request_template: str | None = None,
        response_jsonpath: str | None = None,
        ref: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__()
        if not endpoint:
            raise ValueError("HttpAdapter requires a non-empty endpoint")
        if timeout_seconds <= 0:
            raise ValueError("HttpAdapter timeout_seconds must be > 0")
        if max_retries < 0:
            raise ValueError("HttpAdapter max_retries must be >= 0")
        if max_concurrency <= 0:
            raise ValueError("HttpAdapter max_concurrency must be > 0")

        self._endpoint = endpoint
        self._shape_name = shape
        self._auth_headers = dict(auth_headers or {})
        self._request_template = request_template
        self._response_jsonpath = response_jsonpath
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._shape: HttpShape = get_shape(shape)

        self._owns_client = client is None
        self._client: httpx.AsyncClient = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds)
        )
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._closed = False

        self._fingerprint = TargetFingerprint(
            mode="http",
            ref=ref or endpoint,
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            notes=f"Mode C — production HTTP transport. shape={shape}.",
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def shape_name(self) -> str:
        return self._shape_name

    def _build_headers(self) -> dict[str, str]:
        """Compose request headers from defaults + caller-supplied auth."""
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        headers.update(self._auth_headers)
        return headers

    def _build_body(self, prompt: str, *, session: str | None) -> dict[str, Any]:
        """Build the per-shape request body."""
        if self._shape_name == "generic" and self._request_template is not None:
            # Operator supplied a JSON template; substitute ``{prompt}`` /
            # ``{session}`` placeholders and use that as the body verbatim.
            return _render_request_template(self._request_template, prompt=prompt, session=session)
        return self._shape.build_request(
            prompt,
            model=self._model,
            session=session,
        )

    def _extract_text(self, response_json: dict[str, Any]) -> str:
        """Extract the assistant text from a parsed response body."""
        try:
            if self._shape_name == "generic" and self._response_jsonpath is not None:
                return generic_extract_response_text(
                    response_json, jsonpath=self._response_jsonpath
                )
            return self._shape.extract_response_text(response_json)
        except ValueError as exc:
            msg = str(exc)
            # "produced no value" → format error with "no value" phrase.
            raise LLMResponseFormatError(msg) from exc

    async def _send_once(self, prompt: str, *, session: str | None) -> str:
        """One attempt: build, POST, parse, extract. Raises mapped LLM errors."""
        body = self._build_body(prompt, session=session)
        headers = self._build_headers()
        try:
            resp = await self._client.post(self._endpoint, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(f"http: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise LLMTransientError(f"http: network error: {exc}") from exc
        _raise_for_status(resp)
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise LLMResponseFormatError(f"http: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise LLMResponseFormatError(
                f"http: expected JSON object at top level, got {type(data).__name__}"
            )
        return self._extract_text(data)

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        """Send a prompt and return the assistant text.

        Wires the shape's request builder + extractor through an httpx POST
        with retry/backoff. Raises an :class:`LLMError` subclass on failure
        (auth, rate limit, timeout, transient, permanent, format).
        """
        if self._closed:
            raise RuntimeError("HttpAdapter.call() after aclose()")
        if self._shape_name in _AUTH_DEFERRED_SHAPES:
            raise NotImplementedError(
                f"HttpAdapter shape={self._shape_name!r} requires SigV4 / OAuth2 "
                "auth which is deferred beyond M9. The pure-function shape under "
                "agent_guardian.adapters.http_shapes is still usable for unit "
                "tests; production transport for AWS / GCP signed requests is "
                "an M-future milestone."
            )

        async with self._semaphore:
            return await with_backoff(
                lambda: self._send_once(prompt, session=session),
                max_retries=self._max_retries,
            )

    async def aclose(self) -> None:
        """Close the underlying httpx client if we own it."""
        if self._closed:
            return
        self._closed = True
        if self._owns_client:
            await self._client.aclose()


def _render_request_template(template: str, *, prompt: str, session: str | None) -> dict[str, Any]:
    """Render a JSON request template by substituting ``{prompt}`` / ``{session}``.

    The template is parsed as JSON *after* substitution. Both placeholders
    are escaped via :func:`json.dumps` so prompts that include quotes or
    newlines do not break the template.
    """
    safe_prompt = json.dumps(prompt)[1:-1]  # strip the surrounding quotes
    safe_session = json.dumps(session if session is not None else "")[1:-1]
    rendered = template.replace("{prompt}", safe_prompt).replace("{session}", safe_session)
    try:
        body = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise LLMPermanentError(
            f"http: generic request_template is not valid JSON after substitution: {exc}"
        ) from exc
    if not isinstance(body, dict):
        raise LLMPermanentError("http: generic request_template must render to a JSON object")
    return body


def _raise_for_status(resp: httpx.Response) -> None:
    """Map an HTTP response status to our LLM error hierarchy."""
    if resp.status_code < 400:
        return
    body_preview = resp.text[:512]
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"http: auth failed: {resp.status_code} {body_preview}")
    if resp.status_code == 429:
        retry_after_hdr = resp.headers.get("retry-after")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "http: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("http target 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("http: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"http: transient {resp.status_code}: {body_preview}")
    raise LLMPermanentError(f"http: {resp.status_code} {body_preview}")
