"""Tests for OpenAICompatClient and the OpenAI-compatible gateways.

Every gateway shares the same wire logic; these tests assert the EXACT posted
URL + headers + body via respx so the ``/v1`` path convention (reviewer
correction #1) can never silently regress.
"""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTransientError,
)
from agent_guardian.llm.openai_compat import OpenAICompatClient


def _req(content: str = "hi", model: str = "some-model") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content=content)], model=model)


def _ok_body(model: str = "some-model") -> dict[str, object]:
    return {
        "choices": [{"message": {"content": "ack"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
        "model": model,
    }


_GATEWAYS = [
    ("openrouter", "https://openrouter.ai/api/v1"),
    ("groq", "https://api.groq.com/openai/v1"),
    ("together", "https://api.together.xyz/v1"),
    ("fireworks", "https://api.fireworks.ai/inference/v1"),
]


@pytest.mark.parametrize(("provider", "base_url"), _GATEWAYS)
@respx.mock
async def test_gateway_happy_path_exact_url_and_auth(provider: str, base_url: str) -> None:
    expected_url = f"{base_url}/chat/completions"
    route = respx.post(expected_url).mock(return_value=Response(200, json=_ok_body()))
    llm = OpenAICompatClient(provider=provider, base_url=base_url, api_key="gw-key")
    resp = await llm.complete(_req())
    assert resp.text == "ack"
    assert resp.provider == provider
    assert resp.usage.total_tokens == 4
    sent = route.calls.last.request
    # EXACT URL — guards the ``/v1`` path convention (reviewer correction #1).
    assert str(sent.url) == expected_url
    assert sent.headers["authorization"] == "Bearer gw-key"
    assert sent.headers["content-type"] == "application/json"
    body = json.loads(sent.content)
    assert body["model"] == "some-model"
    await llm.aclose()


@respx.mock
async def test_openrouter_attribution_headers_forwarded() -> None:
    route = respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=Response(200, json=_ok_body())
    )
    llm = OpenAICompatClient(
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        api_key="or-key",
        extra_headers={"HTTP-Referer": "https://example.com", "X-Title": "MyApp"},
    )
    await llm.complete(_req())
    sent = route.calls.last.request
    assert sent.headers["HTTP-Referer"] == "https://example.com"
    assert sent.headers["X-Title"] == "MyApp"
    await llm.aclose()


@respx.mock
async def test_openrouter_extra_usage_fields_do_not_raise() -> None:
    """OpenRouter's extra ``usage.cost`` / ``native_finish_reason`` must parse
    cleanly — selective field extraction, never ``LLMUsage(**usage)``."""
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"content": "hello"},
                        "finish_reason": "stop",
                        "native_finish_reason": "STOP",
                    }
                ],
                "usage": {
                    "prompt_tokens": 5,
                    "completion_tokens": 2,
                    "total_tokens": 7,
                    "cost": 0.00012,
                    "prompt_tokens_details": {"cached_tokens": 0},
                },
                "model": "anthropic/claude-3.5-sonnet",
            },
        )
    )
    llm = OpenAICompatClient(
        provider="openrouter", base_url="https://openrouter.ai/api/v1", api_key="or-key"
    )
    resp = await llm.complete(_req(model="anthropic/claude-3.5-sonnet"))
    assert resp.text == "hello"
    assert resp.usage.total_tokens == 7
    await llm.aclose()


@respx.mock
async def test_vllm_no_api_key_omits_authorization_header() -> None:
    base_url = "http://localhost:8000/v1"
    route = respx.post(f"{base_url}/chat/completions").mock(
        return_value=Response(200, json=_ok_body())
    )
    llm = OpenAICompatClient(provider="vllm", base_url=base_url, api_key=None)
    await llm.complete(_req())
    sent = route.calls.last.request
    assert "authorization" not in {k.lower() for k in sent.headers}
    await llm.aclose()


@respx.mock
async def test_gateway_auth_error() -> None:
    respx.post("https://api.groq.com/openai/v1/chat/completions").mock(
        return_value=Response(401, json={"error": "bad key"})
    )
    llm = OpenAICompatClient(
        provider="groq", base_url="https://api.groq.com/openai/v1", api_key="bad"
    )
    with pytest.raises(LLMAuthError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gateway_rate_limit_persists_raises() -> None:
    respx.post("https://api.together.xyz/v1/chat/completions").mock(
        return_value=Response(429, headers={"retry-after": "0"}, json={"error": "rate"})
    )
    llm = OpenAICompatClient(
        provider="together", base_url="https://api.together.xyz/v1", api_key="k"
    )
    with pytest.raises(LLMRateLimitError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_gateway_transient_500_retries() -> None:
    respx.post("https://api.groq.com/openai/v1/chat/completions").mock(
        side_effect=[Response(500, json={"error": "boom"}), Response(200, json=_ok_body())]
    )
    llm = OpenAICompatClient(
        provider="groq", base_url="https://api.groq.com/openai/v1", api_key="k"
    )
    resp = await llm.complete(_req())
    assert resp.text == "ack"
    await llm.aclose()


@respx.mock
async def test_gateway_malformed_response_raises() -> None:
    respx.post("https://api.fireworks.ai/inference/v1/chat/completions").mock(
        return_value=Response(200, json={"unexpected": "shape"})
    )
    llm = OpenAICompatClient(
        provider="fireworks", base_url="https://api.fireworks.ai/inference/v1", api_key="k"
    )
    with pytest.raises(LLMResponseFormatError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_base_url_trailing_slash_normalised() -> None:
    route = respx.post("https://api.groq.com/openai/v1/chat/completions").mock(
        return_value=Response(200, json=_ok_body())
    )
    llm = OpenAICompatClient(
        provider="groq", base_url="https://api.groq.com/openai/v1/", api_key="k"
    )
    await llm.complete(_req())
    assert str(route.calls.last.request.url) == "https://api.groq.com/openai/v1/chat/completions"
    await llm.aclose()


def test_provider_label_default() -> None:
    llm = OpenAICompatClient(base_url="https://x/v1", api_key="k")
    assert llm.provider == "openai-compat"


@respx.mock
async def test_transient_then_raises_after_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_guardian.llm import retry as retry_mod

    monkeypatch.setattr(retry_mod, "compute_delay", lambda *_a, **_k: 0.0)
    respx.post("https://api.groq.com/openai/v1/chat/completions").mock(
        return_value=Response(503, json={"error": "down"})
    )
    llm = OpenAICompatClient(
        provider="groq", base_url="https://api.groq.com/openai/v1", api_key="k"
    )
    with pytest.raises(LLMTransientError):
        await llm.complete(_req())
    await llm.aclose()
