"""Tests for GeminiClient (AI Studio API) using respx.

Covers the request-shaping rules (``systemInstruction`` split, ``assistant``
→ ``model`` role rename, stop sequences in ``generationConfig``), the
error hierarchy mapping, and the happy-path response parse.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTransientError,
)
from agent_guardian.llm.gemini import GeminiClient

_HAPPY_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview:generateContent"
)


def _req(content: str = "hi", model: str = "gemini-3.1-pro-preview") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content=content)], model=model)


def _happy_body(text: str = "Hello from Gemini") -> dict[str, object]:
    return {
        "candidates": [
            {
                "content": {"parts": [{"text": text}], "role": "model"},
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 5,
            "candidatesTokenCount": 4,
            "totalTokenCount": 9,
        },
        "modelVersion": "gemini-3.1-pro-preview",
    }


@respx.mock
async def test_gemini_complete_happy_path() -> None:
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    llm = GeminiClient(api_key="test-key")
    resp = await llm.complete(_req())
    assert resp.text == "Hello from Gemini"
    assert resp.provider == "gemini"
    assert resp.usage.total_tokens == 9
    assert resp.usage.prompt_tokens == 5
    assert resp.usage.completion_tokens == 4
    assert resp.finish_reason == "stop"
    # The API key travels as a query parameter, not a header.
    assert route.called
    sent_url = urlparse(str(route.calls.last.request.url))
    assert parse_qs(sent_url.query)["key"] == ["test-key"]
    await llm.aclose()


@respx.mock
async def test_gemini_split_system_into_systemInstruction() -> None:
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    req = LLMRequest(
        messages=[
            LLMMessage(role="system", content="You are terse."),
            LLMMessage(role="system", content="No emojis."),
            LLMMessage(role="user", content="hello"),
            LLMMessage(role="assistant", content="hi"),
            LLMMessage(role="user", content="again?"),
        ],
        model="gemini-3.1-pro-preview",
    )
    llm = GeminiClient(api_key="k")
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    # System messages were coalesced into the dedicated field…
    assert body["systemInstruction"]["parts"][0]["text"] == "You are terse.\n\nNo emojis."
    # …and the chat history was preserved with assistant → model rename.
    contents = body["contents"]
    assert [c["role"] for c in contents] == ["user", "model", "user"]
    assert contents[0]["parts"][0]["text"] == "hello"
    assert contents[1]["parts"][0]["text"] == "hi"
    assert contents[2]["parts"][0]["text"] == "again?"
    await llm.aclose()


@respx.mock
async def test_gemini_stop_sequences_serialised_to_generation_config() -> None:
    route = respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy_body()))
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="gemini-3.1-pro-preview",
        stop=["</end>", "STOP"],
        max_tokens=512,
        temperature=0.2,
    )
    llm = GeminiClient(api_key="k")
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    assert body["generationConfig"]["stopSequences"] == ["</end>", "STOP"]
    assert body["generationConfig"]["maxOutputTokens"] == 512
    assert body["generationConfig"]["temperature"] == pytest.approx(0.2)
    await llm.aclose()


@respx.mock
async def test_gemini_auth_401_raises_llm_auth_error() -> None:
    respx.post(_HAPPY_URL).mock(
        return_value=Response(401, json={"error": {"status": "UNAUTHENTICATED"}})
    )
    llm = GeminiClient(api_key="bad")
    with pytest.raises(LLMAuthError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_auth_403_raises_llm_auth_error() -> None:
    respx.post(_HAPPY_URL).mock(
        return_value=Response(403, json={"error": {"status": "PERMISSION_DENIED"}})
    )
    llm = GeminiClient(api_key="forbidden")
    with pytest.raises(LLMAuthError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_rate_limit_429_with_retry_after_eventually_succeeds() -> None:
    route = respx.post(_HAPPY_URL).mock(
        side_effect=[
            Response(429, headers={"retry-after": "0"}, json={"error": "rate"}),
            Response(200, json=_happy_body("ok")),
        ]
    )
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == "ok"
    assert route.call_count == 2
    await llm.aclose()


@respx.mock
async def test_gemini_rate_limit_persists_raises() -> None:
    respx.post(_HAPPY_URL).mock(
        return_value=Response(429, headers={"retry-after": "0"}, json={"error": "rate"})
    )
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMRateLimitError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_transient_503_retries_then_succeeds() -> None:
    respx.post(_HAPPY_URL).mock(
        side_effect=[
            Response(503, json={"error": "service unavailable"}),
            Response(200, json=_happy_body("later")),
        ]
    )
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == "later"
    await llm.aclose()


@respx.mock
async def test_gemini_transient_500_persists_raises_transient_error() -> None:
    respx.post(_HAPPY_URL).mock(return_value=Response(500, json={"error": "boom"}))
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMTransientError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_permanent_400_no_retry() -> None:
    route = respx.post(_HAPPY_URL).mock(
        return_value=Response(400, json={"error": {"status": "INVALID_ARGUMENT"}})
    )
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMPermanentError):
        await llm.complete(_req())
    assert route.call_count == 1
    await llm.aclose()


@respx.mock
async def test_gemini_malformed_response_raises_format_error() -> None:
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json={"unexpected": "shape"}))
    llm = GeminiClient(api_key="k")
    with pytest.raises(LLMResponseFormatError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gemini_finish_reason_max_tokens_maps_to_length() -> None:
    body = _happy_body()
    body["candidates"][0]["finishReason"] = "MAX_TOKENS"  # type: ignore[index]
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.finish_reason == "length"
    await llm.aclose()


@respx.mock
async def test_gemini_finish_reason_safety_maps_to_content_filter() -> None:
    body = _happy_body()
    body["candidates"][0]["finishReason"] = "SAFETY"  # type: ignore[index]
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=body))
    llm = GeminiClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.finish_reason == "content_filter"
    await llm.aclose()


@respx.mock
async def test_gemini_custom_base_url() -> None:
    respx.post("https://proxy.example.com/v1beta/models/gemini-3.5-flash:generateContent").mock(
        return_value=Response(200, json=_happy_body("via proxy"))
    )
    llm = GeminiClient(api_key="k", base_url="https://proxy.example.com/v1beta")
    resp = await llm.complete(_req(model="gemini-3.5-flash"))
    assert resp.text == "via proxy"
    await llm.aclose()


def test_gemini_concurrency_default() -> None:
    llm = GeminiClient(api_key="k")
    # PRD §14.3 default for paid providers without a higher OpenAI-style cap.
    assert llm._semaphore._value == 5
