"""Anthropic Messages API client (PRD §14.3).

Anthropic splits ``system`` out of the message list — we coalesce all
``role=system`` messages into a single ``system`` field, preserving order.
"""

from __future__ import annotations

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

__all__ = ["AnthropicClient"]

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
        url = f"{(self.base_url or _DEFAULT_BASE_URL).rstrip('/')}/v1/messages"
        req = self._client.build_request(
            "POST",
            url,
            json=self._build_payload(request),
            headers=self._headers(),
        )
        try:
            resp = await self._client.send(req)
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(f"anthropic: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise LLMTransientError(f"anthropic: network error: {exc}") from exc
        _raise_for_anthropic_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            raise LLMResponseFormatError(f"anthropic: invalid JSON: {exc}") from exc
        return self._parse_response(request.model, data)

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
                retry_after = None
        raise LLMRateLimitError("anthropic: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"anthropic: transient {resp.status_code}: {resp.text}")
    raise LLMPermanentError(f"anthropic: {resp.status_code} {resp.text}")
