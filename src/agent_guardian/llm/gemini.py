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

import asyncio
import json
import logging
import re
import time
from typing import Any

import httpx

from agent_guardian.llm.base import BaseLLM, LLMMessage, LLMRequest, LLMResponse, LLMUsage
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


# rc38 P0-#5 (#263) — sane upper bound on a single backoff. A misbehaving
# proxy / a typo in the upstream proto can put an absurd ``retryDelay`` on
# the wire ("3600s"); clamping prevents a single 429 from stalling an
# operator-bounded scan for an hour. The retry layer's exponential schedule
# tops out at ~60s on its own, so we mirror that ceiling here.
_RETRY_DELAY_MAX_SECONDS = 60.0

# ``google.rpc.RetryInfo`` carries ``retryDelay`` as a protobuf ``Duration``
# JSON string: a decimal number suffixed with ``s`` (e.g. ``"26.94s"``,
# ``"5s"``). The regex accepts the optional suffix so int-string forms work
# too.
_RETRY_DELAY_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*s?\s*$", re.IGNORECASE)

# Human-readable "retry in Ns" fragment that Gemini puts in ``error.message``
# when the structured RetryInfo block is absent. Tolerant of the surrounding
# prose (anchored on the keyword "retry in", case-insensitive).
_RETRY_MESSAGE_RE = re.compile(
    r"retry\s+in\s+(\d+(?:\.\d+)?)\s*s",
    re.IGNORECASE,
)


def _parse_gemini_retry_delay(body: dict[str, Any] | Any) -> float | None:
    """Extract a retry-delay (seconds) from a Gemini 429 response body.

    Prefers the structured ``google.rpc.RetryInfo`` envelope under
    ``error.details[]`` (``retryDelay`` as a protobuf Duration JSON string).
    Falls back to ``Please retry in Ns`` in ``error.message`` when no
    structured block is present. Returns ``None`` when no hint can be found.

    The returned value is clamped to :data:`_RETRY_DELAY_MAX_SECONDS` so a
    bogus upstream hint cannot stall the scan beyond the legacy exponential
    ceiling.
    """
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if not isinstance(error, dict):
        return None
    details = error.get("details")
    if isinstance(details, list):
        for entry in details:
            if not isinstance(entry, dict):
                continue
            type_url = str(entry.get("@type", ""))
            if "RetryInfo" not in type_url:
                continue
            raw_delay = entry.get("retryDelay")
            if not isinstance(raw_delay, str):
                continue
            match = _RETRY_DELAY_DURATION_RE.match(raw_delay)
            if match is None:
                continue
            try:
                seconds = float(match.group(1))
            except ValueError:
                continue
            return min(max(seconds, 0.0), _RETRY_DELAY_MAX_SECONDS)
    message = error.get("message")
    if isinstance(message, str):
        match = _RETRY_MESSAGE_RE.search(message)
        if match is not None:
            try:
                seconds = float(match.group(1))
            except ValueError:
                return None
            return min(max(seconds, 0.0), _RETRY_DELAY_MAX_SECONDS)
    return None


# rc38 P0-#5 (#263) — token bucket. A free-tier Gemini key burned through
# 3 retries in <10s during the rc38 matrix run because the only gate between
# the swarm and Google was the per-instance semaphore (which bounds
# *concurrency*, not *rate*). The bucket below limits sustained request rate
# to ``capacity / refill_seconds`` (default: 10 calls per minute, a generous
# floor above the free-tier limit) so a burst from a fresh scan smooths out
# rather than triggering a 429 cascade.


class _AsyncTokenBucket:
    """Simple async token bucket gating per-process Gemini request rate.

    ``capacity`` tokens, refilled at ``capacity / refill_seconds`` per
    second. A caller awaits :meth:`acquire` before sending; when the bucket
    is empty the wait pauses until the next token has accrued. The bucket
    is process-local (instances of :class:`GeminiClient` share one by
    default) and uses ``time.monotonic`` so wall-clock changes don't break
    it. Always permits at least one token to accrue per call so a paused
    scan can resume without a permanent stall.
    """

    def __init__(self, *, capacity: int = 10, refill_seconds: float = 60.0) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_seconds <= 0:
            raise ValueError("refill_seconds must be > 0")
        self._capacity = float(capacity)
        self._refill_per_second = capacity / refill_seconds
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until one token is available; consume it."""
        async with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self._last_refill)
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_per_second)
            self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            wait = (1.0 - self._tokens) / self._refill_per_second
        await asyncio.sleep(wait)
        async with self._lock:
            self._tokens = max(0.0, self._tokens - 1.0)
            self._last_refill = time.monotonic()


# Default bucket: 10 requests / 60 seconds (the free-tier RPM floor). Operators
# constructing the client with ``rate_limiter=None`` opt out entirely; passing
# a custom bucket honours their schedule.
_DEFAULT_GEMINI_RATE_LIMITER = _AsyncTokenBucket(capacity=10, refill_seconds=60.0)


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

    # rc38 P0-#5 (#263) — sentinel that distinguishes "not provided (use the
    # per-process default bucket)" from "explicitly disabled (opt-out)".
    # Tests pass ``rate_limiter=None`` to disable; production code constructs
    # with no argument and inherits the default bucket.
    _RATE_LIMITER_DEFAULT: Any = object()

    def __init__(
        self,
        *,
        rate_limiter: _AsyncTokenBucket | None | Any = _RATE_LIMITER_DEFAULT,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if rate_limiter is GeminiClient._RATE_LIMITER_DEFAULT:
            self._rate_limiter: _AsyncTokenBucket | None = _DEFAULT_GEMINI_RATE_LIMITER
        else:
            self._rate_limiter = rate_limiter

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
        # rc38 P0-#5 (#263) — rate gate fires BEFORE the request goes on
        # the wire so a burst smooths out instead of triggering a 429
        # cascade. ``None`` = opt-out for tests.
        if self._rate_limiter is not None:
            await self._rate_limiter.acquire()
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

    async def preflight(self, model: str = "gemini-2.5-flash") -> None:
        """Send one cheap completion to confirm the key is not already
        429'd before a scan commits its budget.

        Raises :class:`LLMRateLimitError` (and ONLY that) on a quota miss
        so the CLI caller can fail-fast with a distinct exit code and a
        clear "Gemini quota exhausted; check your billing" diagnostic.
        Every other failure mode is left to surface on the first real
        completion (auth / network / format).

        rc38 P0-#5 (#263): without this gate, a scan with an exhausted
        free-tier key still spends the recon and seat-prep budgets only
        to hit 429 in flight and degrade silently.
        """
        request = LLMRequest(
            messages=[LLMMessage(role="user", content="ping")],
            model=model,
            max_tokens=1,
            temperature=0.0,
        )
        try:
            await self._send(request)
        except LLMRateLimitError:
            raise
        except Exception as exc:  # pragma: no cover -- defensive
            _LOG.debug("gemini preflight: non-quota error %s — letting real call surface it", exc)


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
        # rc38 P0-#5 (#263) — Gemini ships the retry hint in the response BODY
        # (``error.details[].retryDelay`` per the google.rpc.RetryInfo proto)
        # rather than the Retry-After header. Parse the body when the header
        # was absent so ``with_backoff`` honours the upstream hint instead of
        # burning three exponential attempts in ~10s on a 26.94s quota window.
        if retry_after is None:
            try:
                body = resp.json()
            except (ValueError, json.JSONDecodeError):
                body = None
            retry_after = _parse_gemini_retry_delay(body) if body is not None else None
        _LOG.warning("gemini 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("gemini: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"gemini: transient {resp.status_code}: {resp.text}")
    raise LLMPermanentError(f"gemini: {resp.status_code} {resp.text}")
