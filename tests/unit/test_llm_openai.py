"""Tests for OpenAIClient using respx."""

from __future__ import annotations

import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
)
from agent_guardian.llm.openai import OpenAIClient


def _req(content: str = "hi") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content=content)], model="gpt-4o-mini")


@respx.mock
async def test_openai_happy_path() -> None:
    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "choices": [
                    {"message": {"content": "ack"}, "finish_reason": "stop"},
                ],
                "usage": {
                    "prompt_tokens": 3,
                    "completion_tokens": 1,
                    "total_tokens": 4,
                },
                "model": "gpt-4o-mini",
            },
        )
    )
    llm = OpenAIClient(api_key="sk-test")
    resp = await llm.complete(_req())
    assert resp.text == "ack"
    assert resp.provider == "openai"
    assert resp.usage.total_tokens == 4
    assert resp.finish_reason == "stop"
    assert route.called
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer sk-test"
    await llm.aclose()


@respx.mock
async def test_openai_seed_and_stop_serialized() -> None:
    import json

    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                "model": "gpt-4o-mini",
            },
        )
    )
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="gpt-4o-mini",
        seed=42,
        stop=["</end>"],
    )
    llm = OpenAIClient(api_key="sk-test")
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    assert body["seed"] == 42
    assert body["stop"] == ["</end>"]
    assert body["model"] == "gpt-4o-mini"
    await llm.aclose()


@respx.mock
async def test_openai_auth_error() -> None:
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(401, json={"error": "invalid_api_key"})
    )
    llm = OpenAIClient(api_key="sk-bad")
    import pytest

    with pytest.raises(LLMAuthError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_openai_rate_limit_with_retry_after_eventually_succeeds() -> None:
    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        side_effect=[
            Response(429, headers={"retry-after": "0"}, json={"error": "rate"}),
            Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": "ok"}, "finish_reason": "stop"},
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    "model": "gpt-4o-mini",
                },
            ),
        ]
    )
    llm = OpenAIClient(api_key="sk-test")
    resp = await llm.complete(_req())
    assert resp.text == "ok"
    assert route.call_count == 2
    await llm.aclose()


@respx.mock
async def test_openai_rate_limit_persists_raises() -> None:
    # Always rate limited → exhausts retries → raises LLMRateLimitError
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(429, headers={"retry-after": "0"}, json={"error": "rate"})
    )
    import pytest

    llm = OpenAIClient(api_key="sk-test")
    with pytest.raises(LLMRateLimitError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_openai_transient_500_retries() -> None:
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        side_effect=[
            Response(500, json={"error": "boom"}),
            Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": "later"}, "finish_reason": "stop"},
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    "model": "gpt-4o-mini",
                },
            ),
        ]
    )
    llm = OpenAIClient(api_key="sk-test")
    resp = await llm.complete(_req())
    assert resp.text == "later"
    await llm.aclose()


@respx.mock
async def test_openai_permanent_400_no_retry() -> None:
    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(400, json={"error": "bad request"})
    )
    llm = OpenAIClient(api_key="sk-test")
    import pytest

    with pytest.raises(LLMPermanentError):
        await llm.complete(_req())
    # 400 is non-retryable — exactly 1 call.
    assert route.call_count == 1
    await llm.aclose()


@respx.mock
async def test_openai_malformed_response() -> None:
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(200, json={"unexpected": "shape"})
    )
    llm = OpenAIClient(api_key="sk-test")
    import pytest

    with pytest.raises(LLMResponseFormatError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_openai_invalid_json() -> None:
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(200, content=b"not json")
    )
    llm = OpenAIClient(api_key="sk-test")
    import pytest

    with pytest.raises(LLMResponseFormatError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_openai_custom_base_url() -> None:
    # Reviewer correction #1: ``base_url`` carries the full path prefix; the
    # client appends only ``/chat/completions`` (NOT ``/v1/chat/completions``).
    # A proxy override must therefore include its own ``/v1`` if it needs one.
    respx.post("https://my-proxy.example.com/v1/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                "model": "gpt-4o-mini",
            },
        )
    )
    llm = OpenAIClient(api_key="sk-test", base_url="https://my-proxy.example.com/v1")
    resp = await llm.complete(_req())
    assert resp.text == "x"
    await llm.aclose()


@respx.mock
async def test_openai_default_base_url_posts_v1_path() -> None:
    """Regression guard for reviewer correction #1: the default OpenAI URL
    MUST be ``https://api.openai.com/v1/chat/completions`` (not ``.../chat/...``
    nor ``.../v1/v1/...``)."""
    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                "model": "gpt-4o-mini",
            },
        )
    )
    llm = OpenAIClient(api_key="sk-test")
    await llm.complete(_req())
    assert str(route.calls.last.request.url) == "https://api.openai.com/v1/chat/completions"
    await llm.aclose()


@respx.mock
async def test_openai_finish_reason_length() -> None:
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "choices": [{"message": {"content": "x"}, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                "model": "gpt-4o-mini",
            },
        )
    )
    llm = OpenAIClient(api_key="sk-test")
    resp = await llm.complete(_req())
    assert resp.finish_reason == "length"
    await llm.aclose()


@respx.mock
async def test_openai_429_with_invalid_retry_after_header() -> None:
    """Retry-After header that doesn't parse falls back to computed backoff."""
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        side_effect=[
            Response(429, headers={"retry-after": "soon"}, json={}),
            Response(
                200,
                json={
                    "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    "model": "gpt-4o-mini",
                },
            ),
        ]
    )
    llm = OpenAIClient(api_key="sk-test")
    resp = await llm.complete(_req())
    assert resp.text == "ok"
    await llm.aclose()


def test_openai_concurrency_default() -> None:
    llm = OpenAIClient(api_key="sk-test")
    # PRD §14.3: OpenAI cap = 10.
    assert llm._semaphore._value == 10
