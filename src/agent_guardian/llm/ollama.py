"""Local Ollama client (PRD §14.3).

Ollama runs locally with no auth, on ``http://localhost:11434`` by default.
This client is the recommended local-development backend.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.errors import (
    LLMPermanentError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import with_backoff
from agent_guardian.logging_setup import log_model_request, log_model_response

__all__ = ["OllamaClient"]

_LOG = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "http://localhost:11434"

_FINISH_REASON_MAP = {
    "stop": "stop",
    "length": "length",
}


class OllamaClient(BaseLLM):
    """Ollama provider client."""

    provider = "ollama"
    default_max_concurrency = 5

    def _build_payload(self, request: LLMRequest) -> dict[str, Any]:
        options: dict[str, Any] = {
            "temperature": request.temperature,
            "num_predict": request.max_tokens,
        }
        if request.seed is not None:
            options["seed"] = request.seed
        if request.stop is not None:
            options["stop"] = list(request.stop)
        return {
            "model": request.model,
            "messages": [{"role": m.role, "content": m.content} for m in request.messages],
            "stream": False,
            "options": options,
        }

    @staticmethod
    def _parse_response(model: str, data: dict[str, Any]) -> LLMResponse:
        try:
            message = data.get("message") or {}
            text = message.get("content", "") or ""
            prompt_tokens = int(data.get("prompt_eval_count", 0) or 0)
            completion_tokens = int(data.get("eval_count", 0) or 0)
            raw_finish = data.get("done_reason") or "stop"
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMResponseFormatError(f"ollama: malformed response: {exc}") from exc
        return LLMResponse(
            text=text,
            model=data.get("model", model),
            provider="ollama",
            usage=LLMUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
            raw=data,
        )

    async def _send(self, request: LLMRequest) -> LLMResponse:
        url = f"{(self.base_url or _DEFAULT_BASE_URL).rstrip('/')}/api/chat"
        payload = self._build_payload(request)
        # One coherent block per call (provider+model stamped once on the INFO
        # narration line emitted here); the full request out lands at DEBUG.
        log_model_request(
            _LOG,
            provider="ollama",
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
            headers={"content-type": "application/json"},
        )
        try:
            resp = await self._client.send(req)
        except httpx.TimeoutException as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTimeoutError(f"ollama: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTransientError(f"ollama: network error: {exc}") from exc
        _raise_for_ollama_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMResponseFormatError(f"ollama: invalid JSON: {exc}") from exc
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


def _raise_for_ollama_status(resp: httpx.Response) -> None:
    """Map an Ollama HTTP response to our error hierarchy.

    Ollama is local, has no auth and no rate limit. Anything 5xx is a transient
    server hiccup; 4xx is a programming error.
    """
    if resp.status_code < 400:
        return
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"ollama: transient {resp.status_code}: {resp.text}")
    raise LLMPermanentError(f"ollama: {resp.status_code} {resp.text}")
