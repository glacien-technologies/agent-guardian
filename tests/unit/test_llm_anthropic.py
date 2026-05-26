"""Tests for AnthropicClient."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from agent_guardian.llm.anthropic import AnthropicClient
from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTransientError,
)


def _req(content: str = "hi") -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="user", content=content)],
        model="claude-3-5-sonnet",
    )


@respx.mock
async def test_anthropic_happy_path() -> None:
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(
            200,
            json={
                "content": [{"type": "text", "text": "hello"}],
                "usage": {"input_tokens": 10, "output_tokens": 5},
                "stop_reason": "end_turn",
                "model": "claude-3-5-sonnet",
            },
        )
    )
    llm = AnthropicClient(api_key="ant-test")
    resp = await llm.complete(_req())
    assert resp.text == "hello"
    assert resp.provider == "anthropic"
    assert resp.usage.prompt_tokens == 10
    assert resp.usage.completion_tokens == 5
    assert resp.usage.total_tokens == 15
    sent = route.calls.last.request
    assert sent.headers["x-api-key"] == "ant-test"
    assert sent.headers["anthropic-version"] == "2023-06-01"
    await llm.aclose()


@respx.mock
async def test_anthropic_coalesces_system_messages() -> None:
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(
            200,
            json={
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "stop_reason": "end_turn",
                "model": "c",
            },
        )
    )
    req = LLMRequest(
        messages=[
            LLMMessage(role="system", content="first"),
            LLMMessage(role="system", content="second"),
            LLMMessage(role="user", content="hi"),
        ],
        model="c",
    )
    llm = AnthropicClient(api_key="k")
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    assert body["system"] == "first\n\nsecond"
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    await llm.aclose()


@respx.mock
async def test_anthropic_omits_system_when_none() -> None:
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(
            200,
            json={
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "stop_reason": "end_turn",
            },
        )
    )
    llm = AnthropicClient(api_key="k")
    await llm.complete(_req())
    body = json.loads(route.calls.last.request.content)
    assert "system" not in body
    await llm.aclose()


@respx.mock
async def test_anthropic_stop_sequences() -> None:
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(
            200,
            json={
                "content": [{"type": "text", "text": "x"}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "stop_reason": "stop_sequence",
            },
        )
    )
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="c",
        stop=["END"],
    )
    llm = AnthropicClient(api_key="k")
    resp = await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    assert body["stop_sequences"] == ["END"]
    assert resp.finish_reason == "stop"
    await llm.aclose()


@respx.mock
async def test_anthropic_finish_reason_mapping() -> None:
    cases = [
        ("end_turn", "stop"),
        ("max_tokens", "length"),
        ("tool_use", "tool_call"),
        ("unknown_thing", "stop"),
    ]
    for raw, expected in cases:
        respx.post("https://api.anthropic.com/v1/messages").mock(
            return_value=Response(
                200,
                json={
                    "content": [{"type": "text", "text": "x"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                    "stop_reason": raw,
                },
            )
        )
        llm = AnthropicClient(api_key="k")
        resp = await llm.complete(_req())
        assert resp.finish_reason == expected, raw
        await llm.aclose()
        respx.reset()


@respx.mock
async def test_anthropic_auth_error() -> None:
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(401, json={"error": "bad key"})
    )
    llm = AnthropicClient(api_key="bad")
    with pytest.raises(LLMAuthError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_anthropic_rate_limit_with_retry_after() -> None:
    respx.post("https://api.anthropic.com/v1/messages").mock(
        side_effect=[
            Response(429, headers={"retry-after": "0"}, json={"error": "rate"}),
            Response(
                200,
                json={
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                    "stop_reason": "end_turn",
                },
            ),
        ]
    )
    llm = AnthropicClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == "ok"
    await llm.aclose()


@respx.mock
async def test_anthropic_persistent_rate_limit() -> None:
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(429, headers={"retry-after": "0"}, json={})
    )
    llm = AnthropicClient(api_key="k")
    with pytest.raises(LLMRateLimitError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_anthropic_transient_503_retries() -> None:
    respx.post("https://api.anthropic.com/v1/messages").mock(
        side_effect=[
            Response(503, json={"error": "overloaded"}),
            Response(
                200,
                json={
                    "content": [{"type": "text", "text": "later"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                    "stop_reason": "end_turn",
                },
            ),
        ]
    )
    llm = AnthropicClient(api_key="k")
    resp = await llm.complete(_req())
    assert resp.text == "later"
    await llm.aclose()


@respx.mock
async def test_anthropic_permanent_400() -> None:
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(400, json={"error": "bad"})
    )
    llm = AnthropicClient(api_key="k")
    with pytest.raises(LLMPermanentError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_anthropic_malformed_response() -> None:
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=Response(200, content=b"not json")
    )
    llm = AnthropicClient(api_key="k")
    with pytest.raises(LLMResponseFormatError):
        await llm.complete(_req())
    await llm.aclose()


def test_anthropic_concurrency_default() -> None:
    llm = AnthropicClient(api_key="k")
    # PRD §14.3: Anthropic cap = 5.
    assert llm._semaphore._value == 5


def test_anthropic_module_exports_transient_error_symbol() -> None:
    # smoke: symbol is exported even if not used in a per-test branch
    assert issubclass(LLMTransientError, Exception)
