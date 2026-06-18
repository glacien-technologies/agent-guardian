"""Gemini retry-delay parsing from the 429 response body (rc38 P0-#5 / #263).

Verbatim symptom: ``gemini 429 rate limited (retry_after=None)`` despite the
429 payload carrying ``retryInfo.retryDelay = "26.94s"`` (Google's standard
``google.rpc.RetryInfo`` envelope) or the human-readable ``Please retry in
26.94s`` string in ``error.message``.

The pre-fix retry layer ignored the structured hint and burned every attempt
within ~10s. The fix parses both shapes and surfaces a positive
``retry_after`` on the :class:`LLMRateLimitError`, which the shared
``with_backoff`` helper already honours.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from agent_guardian.llm.errors import LLMRateLimitError
from agent_guardian.llm.gemini import GeminiClient, _parse_gemini_retry_delay

_HAPPY_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview:generateContent"
)


def test_parse_retry_delay_from_google_rpc_retryinfo() -> None:
    """Standard ``google.rpc.RetryInfo`` envelope under ``error.details``."""
    body = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "26.94s",
                }
            ],
        }
    }
    assert _parse_gemini_retry_delay(body) == pytest.approx(26.94, rel=1e-3)


def test_parse_retry_delay_falls_back_to_message_string() -> None:
    """``Please retry in Ns`` lifted out of ``error.message`` when no structured
    RetryInfo block is present."""
    body = {
        "error": {
            "code": 429,
            "message": "Quota exceeded. Please retry in 12.5s.",
            "status": "RESOURCE_EXHAUSTED",
        }
    }
    assert _parse_gemini_retry_delay(body) == pytest.approx(12.5, rel=1e-3)


def test_parse_retry_delay_clamps_to_sane_max() -> None:
    """An absurd hint (e.g. 3600s on a misbehaving proxy) is clamped to the
    sane per-process max so a single 429 cannot stall the scan for an hour."""
    body = {
        "error": {
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "3600s",
                }
            ]
        }
    }
    parsed = _parse_gemini_retry_delay(body)
    assert parsed is not None
    assert parsed <= 60.0, f"expected clamp to 60s, got {parsed}"


def test_parse_retry_delay_returns_none_when_absent() -> None:
    """No retry hint anywhere → ``None`` so the shared backoff helper falls back
    to its exponential schedule (the legacy behaviour)."""
    assert _parse_gemini_retry_delay({"error": {"code": 429}}) is None
    assert _parse_gemini_retry_delay({}) is None
    assert _parse_gemini_retry_delay({"error": {"message": "rate limited"}}) is None


def test_parse_retry_delay_handles_int_seconds_string() -> None:
    """``retryDelay`` is sometimes serialised without the trailing 's'."""
    body = {
        "error": {
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "5",
                }
            ]
        }
    }
    assert _parse_gemini_retry_delay(body) == pytest.approx(5.0, rel=1e-3)


@respx.mock
async def test_gemini_429_surfaces_retry_after_from_body() -> None:
    """End-to-end: a 429 body with RetryInfo must produce
    ``LLMRateLimitError.retry_after = 26.94`` so ``with_backoff`` honours it.

    Bypasses the retry layer with ``_send`` directly so the assertion is
    immediate (the retry layer would otherwise honour our newly-parsed
    26.94s delay and make the test slow — the assertion under test is
    purely that the value is surfaced)."""
    body = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "message": "Quota exceeded",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "26.94s",
                }
            ],
        }
    }
    respx.post(_HAPPY_URL).mock(return_value=Response(429, json=body))
    llm = GeminiClient(api_key="k")
    from agent_guardian.llm.base import LLMMessage, LLMRequest

    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")], model="gemini-3.1-pro-preview"
    )
    with pytest.raises(LLMRateLimitError) as excinfo:
        await llm._send(req)
    assert excinfo.value.retry_after is not None
    assert excinfo.value.retry_after == pytest.approx(26.94, rel=1e-3)
    await llm.aclose()


@respx.mock
async def test_gemini_429_message_only_surfaces_retry_after() -> None:
    """When only ``error.message`` carries the hint, the parser still wins.

    Bypasses the retry layer via ``_send`` so the assertion is immediate."""
    body = {
        "error": {
            "code": 429,
            "message": "You exceeded your current quota. Please retry in 7.5s.",
            "status": "RESOURCE_EXHAUSTED",
        }
    }
    respx.post(_HAPPY_URL).mock(return_value=Response(429, json=body))
    llm = GeminiClient(api_key="k")
    from agent_guardian.llm.base import LLMMessage, LLMRequest

    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")], model="gemini-3.1-pro-preview"
    )
    with pytest.raises(LLMRateLimitError) as excinfo:
        await llm._send(req)
    assert excinfo.value.retry_after is not None
    assert excinfo.value.retry_after == pytest.approx(7.5, rel=1e-3)
    await llm.aclose()
