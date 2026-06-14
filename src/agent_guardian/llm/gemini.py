"""Google Gemini (AI Studio) chat completion client (PRD §14.3).

Uses the simple API-key-in-URL auth flow against
``https://generativelanguage.googleapis.com/v1beta`` — **not** the OAuth2
Vertex AI path served by ``aiplatform.googleapis.com``. Compatible with
every Gemini 2.5+ / 3.x model exposed via AI Studio.

The Gemini Generative Language API is a separate surface from Vertex AI.
The Vertex client (``vertex.py``) stays for users running on GCP with
service-account auth; this client is the low-friction option for users
with a plain API key from https://aistudio.google.com/app/apikey.
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

__all__ = ["GeminiClient"]

_LOG = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

# Gemini → our FinishReason normalisation table.
_FINISH_REASON_MAP = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
    "PROHIBITED_CONTENT": "content_filter",
    "BLOCKLIST": "content_filter",
    "SPII": "content_filter",
}


class GeminiClient(BaseLLM):
    """Google Gemini chat completion provider client (AI Studio endpoint).

    Validation of the model name happens server-side — we accept any model
    string (``gemini-3.1-pro-preview``, ``gemini-3.5-flash``,
    ``gemini-2.5-flash``…) and let the API decide. The :mod:`cost` table
    ships rows for the well-known SKUs so the pre-flight USD estimate is
    informative for the common models.
    """

    provider = "gemini"
    default_max_concurrency = 5

    def _build_payload(self, request: LLMRequest) -> dict[str, Any]:
        # System messages go into the dedicated ``systemInstruction`` field;
        # the rest of the conversation goes in ``contents`` with the
        # assistant role renamed to ``model``.
        system_parts: list[str] = []
        contents: list[dict[str, Any]] = []
        for msg in request.messages:
            if msg.role == "system":
                system_parts.append(msg.content)
                continue
            role = "model" if msg.role == "assistant" else msg.role
            contents.append({"role": role, "parts": [{"text": msg.content}]})

        generation_config: dict[str, Any] = {
            "temperature": request.temperature,
            "maxOutputTokens": request.max_tokens,
        }
        if request.seed is not None:
            # Gemini accepts the deterministic seed inside ``generationConfig``
            # (camelCase ``seed``) for AI Studio v1beta. Forward it so swarm
            # replay buys actual determinism — not just the same prompt.
            generation_config["seed"] = request.seed
        if request.stop is not None:
            generation_config["stopSequences"] = list(request.stop)

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": generation_config,
        }
        if system_parts:
            payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
        return payload

    @staticmethod
    def _parse_response(model: str, data: dict[str, Any]) -> LLMResponse:
        try:
            candidate = data["candidates"][0]
            # Thinking models (gemini-2.5-pro and newer) can return a candidate
            # whose ``content`` has NO ``parts`` at all — typically when
            # ``finishReason=MAX_TOKENS`` because every output token was spent
            # on internal "thoughts". That is a *valid* (if empty) response,
            # not a malformed one: raising here used to kill the whole attack
            # lane on the first such turn (#133). Mirror the tolerant Vertex
            # parser: empty text + the mapped finish_reason, and let callers
            # apply their empty-output fallbacks.
            parts = (candidate.get("content") or {}).get("parts") or []
            text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
            usage_meta = data.get("usageMetadata") or {}
            raw_finish = candidate.get("finishReason", "STOP") or "STOP"
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMResponseFormatError(f"gemini: malformed response: {exc}") from exc
        if not text:
            # Gemini returns ``text=""`` for several distinct upstream failure
            # modes, each of which needs a different remediation. Issue #197 —
            # a single WARN line was conflating thinking-budget exhaustion
            # (raise ``max_output_tokens``) with structural failures
            # (``MALFORMED_FUNCTION_CALL`` — no token tuning will help) and
            # safety-filter blocks (``SAFETY`` / ``RECITATION`` — caller's
            # fallback IS the correct path, not a bug). Operators triaging
            # these logs were being sent down the budget-tuning road for
            # symptoms that were actually structural or content-policy. Split
            # the message by ``finishReason`` so the diagnostic guides the
            # correct remediation.
            thought_tokens = int((data.get("usageMetadata") or {}).get("thoughtsTokenCount", 0))
            if raw_finish == "MALFORMED_FUNCTION_CALL":
                _LOG.warning(
                    "gemini: empty candidate text (finishReason=MALFORMED_FUNCTION_CALL) — "
                    "model emitted a malformed function-call payload; returning empty text "
                    "for the caller's fallback path (raising max_output_tokens will NOT help)"
                )
            elif raw_finish in ("MAX_TOKENS", "STOP") and thought_tokens > 0:
                _LOG.warning(
                    "gemini: empty candidate text (finishReason=%s, thoughtsTokenCount=%d) — "
                    "a thinking model consumed the whole max_output_tokens budget on "
                    "reasoning; raise max_output_tokens to see real text",
                    raw_finish,
                    thought_tokens,
                )
            elif raw_finish in ("SAFETY", "RECITATION"):
                _LOG.info(
                    "gemini: empty candidate text (finishReason=%s) — provider safety/"
                    "recitation filter blocked the response; caller's fallback path will "
                    "handle it",
                    raw_finish,
                )
            else:
                _LOG.warning(
                    "gemini: empty candidate text (finishReason=%s, thoughtsTokenCount=%d) — "
                    "unrecognised empty-response shape; returning empty text for fallback",
                    raw_finish,
                    thought_tokens,
                )
        prompt_tokens = int(usage_meta.get("promptTokenCount", 0))
        completion_tokens = int(usage_meta.get("candidatesTokenCount", 0))
        total_tokens = int(usage_meta.get("totalTokenCount", prompt_tokens + completion_tokens))
        return LLMResponse(
            text=text,
            model=data.get("modelVersion", model),
            provider="gemini",
            usage=LLMUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
            ),
            finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
            raw=data,
        )

    async def _send(self, request: LLMRequest) -> LLMResponse:
        base = (self.base_url or _DEFAULT_BASE_URL).rstrip("/")
        url = f"{base}/models/{request.model}:generateContent"
        params: dict[str, str] = {}
        if self.api_key:
            params["key"] = self.api_key
        payload = self._build_payload(request)
        # One coherent block per call (provider+model stamped once on the INFO
        # narration line emitted here); the full request out lands at DEBUG.
        log_model_request(
            _LOG,
            provider="gemini",
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
            params=params,
            json=payload,
            headers={"content-type": "application/json"},
        )
        try:
            resp = await self._client.send(req)
        except httpx.TimeoutException as exc:  # pragma: no cover — covered by openai timeout test
            log_model_response(_LOG, error=exc)
            raise LLMTimeoutError(f"gemini: timeout: {exc}") from exc
        except httpx.HTTPError as exc:  # pragma: no cover — covered by openai network test
            log_model_response(_LOG, error=exc)
            raise LLMTransientError(f"gemini: network error: {exc}") from exc
        _raise_for_gemini_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:  # pragma: no cover — covered by openai invalid-JSON test
            log_model_response(_LOG, error=exc)
            raise LLMResponseFormatError(f"gemini: invalid JSON: {exc}") from exc
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


def _raise_for_gemini_status(resp: httpx.Response) -> None:
    """Map a Gemini HTTP response to our error hierarchy."""
    if resp.status_code < 400:
        return
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"gemini: auth failed: {resp.status_code} {resp.text}")
    if resp.status_code == 429:
        retry_after_hdr = resp.headers.get("retry-after") or resp.headers.get("Retry-After")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "gemini: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("gemini 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("gemini: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"gemini: transient {resp.status_code}: {resp.text}")
    raise LLMPermanentError(f"gemini: {resp.status_code} {resp.text}")
