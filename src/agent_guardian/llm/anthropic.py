"""Anthropic Messages API client (PRD §14.3).

Anthropic splits ``system`` out of the message list — we coalesce all
``role=system`` messages into a single ``system`` field, preserving order.
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

__all__ = ["AnthropicClient"]

_LOG = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.anthropic.com"
_API_VERSION = "2023-06-01"

_FINISH_REASON_MAP = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "tool_use": "tool_call",
}


class AnthropicClient(BaseLLM):
    """Anthropic Messages API provider client."""

    provider = "anthropic"
    default_max_concurrency = 5

    # Class-level flag so the "seed not supported" debug warning is emitted
    # at most once per process — protects log volume during long swarm runs
    # where every replay would otherwise re-log the same notice.
    _seed_warning_emitted: bool = False

    def _maybe_warn_seed_ignored(self, request: LLMRequest) -> None:
        if request.seed is None:
            return
        if AnthropicClient._seed_warning_emitted:
            return
        AnthropicClient._seed_warning_emitted = True
        _LOG.debug(
            "anthropic: provider does not support seed; ignoring "
            "(deterministic replay unavailable for this provider)"
        )

    def _build_payload(self, request: LLMRequest) -> dict[str, Any]:
        system_parts: list[str] = []
        messages: list[dict[str, Any]] = []
        for msg in request.messages:
            if msg.role == "system":
                system_parts.append(msg.content)
            else:
                messages.append({"role": msg.role, "content": msg.content})
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if request.stop is not None:
            payload["stop_sequences"] = list(request.stop)
        return payload

    def _headers(self) -> dict[str, str]:
        headers = {
            "content-type": "application/json",
            "anthropic-version": _API_VERSION,
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    @staticmethod
    def _parse_response(model: str, data: dict[str, Any]) -> LLMResponse:
        try:
            blocks = data.get("content") or []
            text_parts = [b.get("text", "") for b in blocks if b.get("type", "text") == "text"]
            text = "".join(text_parts)
            usage = data.get("usage") or {}
            raw_finish = data.get("stop_reason") or "end_turn"
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMResponseFormatError(f"anthropic: malformed response: {exc}") from exc
        prompt_tokens = int(usage.get("input_tokens", 0))
        completion_tokens = int(usage.get("output_tokens", 0))
        return LLMResponse(
            text=text,
            model=data.get("model", model),
            provider="anthropic",
            usage=LLMUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
            raw=data,
        )

    async def _send(self, request: LLMRequest) -> LLMResponse:
        self._maybe_warn_seed_ignored(request)
        url = f"{(self.base_url or _DEFAULT_BASE_URL).rstrip('/')}/v1/messages"
        payload = self._build_payload(request)
        # One coherent block per call (provider+model stamped once on the INFO
        # narration line emitted here); the full request out lands at DEBUG.
        # ``seed`` is not forwarded by this provider (see _maybe_warn_seed_ignored)
        # so we don't log it as if it were honoured.
        log_model_request(
            _LOG,
            provider="anthropic",
            model=request.model,
            n_messages=len(request.messages),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
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
            _LOG.warning("anthropic timeout: %s", exc)
            raise LLMTimeoutError(f"anthropic: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            _LOG.warning("anthropic network error: %s: %s", type(exc).__name__, exc)
            raise LLMTransientError(f"anthropic: network error: {exc}") from exc
        _raise_for_anthropic_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            _LOG.warning("anthropic invalid JSON in 2xx response: %s", exc)
            raise LLMResponseFormatError(f"anthropic: invalid JSON: {exc}") from exc
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


def _raise_for_anthropic_status(resp: httpx.Response) -> None:
    """Map an Anthropic HTTP response to our error hierarchy."""
    if resp.status_code < 400:
        return
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"anthropic: auth failed: {resp.status_code} {resp.text}")
    if resp.status_code == 429:
        retry_after_hdr = resp.headers.get("retry-after")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "anthropic: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("anthropic 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("anthropic: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"anthropic: transient {resp.status_code}: {resp.text}")
    raise LLMPermanentError(f"anthropic: {resp.status_code} {resp.text}")
