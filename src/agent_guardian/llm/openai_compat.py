"""OpenAI-compatible Chat Completions client (PRD §14.3).

A single parametric :class:`OpenAICompatClient` covers OpenAI itself and the
growing family of OpenAI-wire-format gateways — OpenRouter, Groq, Together,
Fireworks, vLLM — plus Azure OpenAI (via the :mod:`agent_guardian.llm.azure_openai`
subclass). All of them speak the same ``POST {base_url}/chat/completions``
contract; the only axes of variation are:

* ``base_url`` — each gateway ships its own fully-versioned base URL
  (e.g. ``https://api.groq.com/openai/v1``). OpenAI's own default is
  ``https://api.openai.com/v1`` — the ``/v1`` is part of the base URL, not
  appended by this client (reviewer correction #1).
* ``api_key`` — ``None`` means "send no ``Authorization`` header" (vLLM's
  unauthenticated mode).
* ``extra_headers`` — provider-specific attribution headers (OpenRouter's
  ``HTTP-Referer`` / ``X-Title``).
* ``provider`` — the label stamped onto :class:`LLMResponse` and error strings.

Response parsing is deliberately *tolerant*: we extract the individual fields
we need (``choices[0].message.content``, ``usage.{prompt,completion,total}_tokens``)
rather than splatting the provider's ``usage`` block into :class:`LLMUsage`,
which has ``extra='forbid'``. That keeps OpenRouter's extra ``usage.cost`` /
``native_finish_reason`` fields from raising.
"""

from __future__ import annotations

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

__all__ = ["OpenAICompatClient"]

_LOG = logging.getLogger(__name__)

# OpenAI → our FinishReason normalisation table. Shared by every
# OpenAI-compatible gateway; unknown reasons collapse to ``stop``.
_FINISH_REASON_MAP = {
    "stop": "stop",
    "length": "length",
    "tool_calls": "tool_call",
    "function_call": "tool_call",
    "content_filter": "content_filter",
}


class OpenAICompatClient(BaseLLM):
    """OpenAI-compatible Chat Completions provider client.

    Parametric over ``(provider, base_url, api_key, extra_headers)`` so a
    single implementation serves OpenAI and every OpenAI-wire-format gateway.
    ``_send`` posts to ``{base_url.rstrip('/')}/chat/completions`` — the
    ``base_url`` MUST already include the provider's path prefix (``/v1``,
    ``/openai/v1``, ``/inference/v1``, …).
    """

    provider = "openai-compat"
    default_max_concurrency = 10

    def __init__(
        self,
        *,
        provider: str | None = None,
        base_url: str,
        api_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(api_key=api_key, base_url=base_url, **kwargs)
        if provider is not None:
            # Per-instance override of the class attribute so the same class
            # can stamp ``openrouter`` / ``groq`` / … on its responses.
            self.provider = provider
        self._extra_headers = dict(extra_headers or {})

    def _build_payload(self, request: LLMRequest) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        if request.seed is not None:
            payload["seed"] = request.seed
        if request.stop is not None:
            payload["stop"] = list(request.stop)
        return payload

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        headers.update(self._extra_headers)
        return headers

    def _request_url(self) -> str:
        # ``base_url`` already carries the full versioned path prefix; we only
        # append the resource path. Subclasses (Azure) override for their
        # deployment + api-version URL shape.
        return f"{(self.base_url or '').rstrip('/')}/chat/completions"

    async def _prepare_request(self) -> None:
        """Async hook run inside ``_send`` before the request is built.

        The default is a no-op so the api-key path pays nothing. Subclasses that
        must mint a credential via blocking SDK I/O (Azure Entra ID) override
        this to refresh+cache the token off the event loop, so the synchronous
        :meth:`_headers` can read it without blocking the loop.
        """
        return None

    def _parse_response(self, model: str, data: dict[str, Any]) -> LLMResponse:
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"] or ""
            usage = data.get("usage") or {}
            raw_finish = choice.get("finish_reason", "stop") or "stop"
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMResponseFormatError(f"{self.provider}: malformed response: {exc}") from exc
        return LLMResponse(
            text=text,
            model=data.get("model", model),
            provider=self.provider,
            # Selective field extraction — never ``LLMUsage(**usage)``: the
            # usage block can carry extra keys (OpenRouter's ``cost``,
            # ``prompt_tokens_details``) that ``extra='forbid'`` would reject.
            usage=LLMUsage(
                prompt_tokens=int(usage.get("prompt_tokens", 0)),
                completion_tokens=int(usage.get("completion_tokens", 0)),
                total_tokens=int(usage.get("total_tokens", 0)),
            ),
            finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
            raw=data,
        )

    async def _send(self, request: LLMRequest) -> LLMResponse:
        await self._prepare_request()
        url = self._request_url()
        payload = self._build_payload(request)
        # One coherent block per call (provider+model stamped once on the INFO
        # narration line emitted here); the full request out lands at DEBUG.
        log_model_request(
            _LOG,
            provider=self.provider,
            model=request.model,
            n_messages=len(request.messages),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            seed=request.seed,
            request_body=payload,
            messages=request.messages,
        )
        req = self._client.build_request(
            "POST",
            url,
            json=payload,
            headers=self._headers(),
        )
        try:
            resp = await self._client.send(req)
        except httpx.TimeoutException as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTimeoutError(f"{self.provider}: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTransientError(f"{self.provider}: network error: {exc}") from exc
        self._raise_for_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMResponseFormatError(f"{self.provider}: invalid JSON: {exc}") from exc
        parsed = self._parse_response(request.model, data)
        # Response in — full text + usage + finish; a content_filter finish is
        # surfaced at WARNING by the helper rather than swallowed.
        log_model_response(
            _LOG,
            response_text=parsed.text,
            usage=parsed.usage,
            finish_reason=parsed.finish_reason,
        )
        return parsed

    def _raise_for_status(self, resp: httpx.Response) -> None:
        """Map an OpenAI-compatible HTTP response to our error hierarchy."""
        if resp.status_code < 400:
            return
        if resp.status_code in (401, 403):
            raise LLMAuthError(f"{self.provider}: auth failed: {resp.status_code} {resp.text}")
        if resp.status_code == 429:
            retry_after_hdr = resp.headers.get("retry-after")
            retry_after: float | None = None
            if retry_after_hdr is not None:
                try:
                    retry_after = float(retry_after_hdr)
                except ValueError:
                    _LOG.debug(
                        "%s: unparseable Retry-After header %r — backoff will use default",
                        self.provider,
                        retry_after_hdr,
                    )
                    retry_after = None
            _LOG.warning("%s 429 rate limited (retry_after=%s)", self.provider, retry_after)
            raise LLMRateLimitError(f"{self.provider}: rate limited", retry_after=retry_after)
        if resp.status_code == 408 or resp.status_code >= 500:
            raise LLMTransientError(f"{self.provider}: transient {resp.status_code}: {resp.text}")
        raise LLMPermanentError(f"{self.provider}: {resp.status_code} {resp.text}")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        async with self._semaphore:
            return await with_backoff(lambda: self._send(request))
