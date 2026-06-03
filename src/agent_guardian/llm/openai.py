"""OpenAI Chat Completions client (PRD §14.3).

Implements the bare-minimum surface AgentGuardian needs: synchronous chat
completion mapped to :class:`LLMResponse`. Streaming, tools, vision, etc. are
out of scope for the OSS edition.
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

__all__ = ["OpenAIClient"]

_LOG = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.openai.com"

# OpenAI → our FinishReason normalisation table.
_FINISH_REASON_MAP = {
    "stop": "stop",
    "length": "length",
    "tool_calls": "tool_call",
    "function_call": "tool_call",
    "content_filter": "content_filter",
}


class OpenAIClient(BaseLLM):
    """OpenAI Chat Completions provider client."""

    provider = "openai"
    default_max_concurrency = 10

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
        return headers

    @staticmethod
    def _parse_response(model: str, data: dict[str, Any]) -> LLMResponse:
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"] or ""
            usage = data.get("usage") or {}
            raw_finish = choice.get("finish_reason", "stop") or "stop"
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMResponseFormatError(f"openai: malformed response: {exc}") from exc
        return LLMResponse(
            text=text,
            model=data.get("model", model),
            provider="openai",
            usage=LLMUsage(
                prompt_tokens=int(usage.get("prompt_tokens", 0)),
                completion_tokens=int(usage.get("completion_tokens", 0)),
                total_tokens=int(usage.get("total_tokens", 0)),
            ),
            finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
            raw=data,
        )

    async def _send(self, request: LLMRequest) -> LLMResponse:
        url = f"{(self.base_url or _DEFAULT_BASE_URL).rstrip('/')}/v1/chat/completions"
        payload = self._build_payload(request)
        # One coherent block per call (provider+model stamped once on the INFO
        # narration line emitted here); the full request out lands at DEBUG.
        log_model_request(
            _LOG,
            provider="openai",
            model=request.model,
            n_messages=len(request.messages),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            seed=request.seed,
            request_body=payload,
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
            _LOG.warning("openai timeout: %s", exc)
            raise LLMTimeoutError(f"openai: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            _LOG.warning("openai network error: %s: %s", type(exc).__name__, exc)
            raise LLMTransientError(f"openai: network error: {exc}") from exc
        _raise_for_openai_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            _LOG.warning("openai invalid JSON in 2xx response: %s", exc)
            raise LLMResponseFormatError(f"openai: invalid JSON: {exc}") from exc
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

    async def complete(self, request: LLMRequest) -> LLMResponse:
        async with self._semaphore:
            return await with_backoff(lambda: self._send(request))


def _raise_for_openai_status(resp: httpx.Response) -> None:
    """Map an OpenAI HTTP response to our error hierarchy."""
    if resp.status_code < 400:
        return
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"openai: auth failed: {resp.status_code} {resp.text}")
    if resp.status_code == 429:
        retry_after_hdr = resp.headers.get("retry-after")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "openai: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("openai 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("openai: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"openai: transient {resp.status_code}: {resp.text}")
    raise LLMPermanentError(f"openai: {resp.status_code} {resp.text}")
