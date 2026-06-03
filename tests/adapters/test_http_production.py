"""Production transport tests for :class:`HttpAdapter` (M9).

We mock the wire with :mod:`respx`. Each of the three "fully wired" shapes
(``openai``, ``anthropic``, ``generic``) is exercised against a realistic
response payload. We also assert:

* Auth headers are injected on the outbound request.
* 429 + ``Retry-After`` triggers a retry honouring the header.
* 5xx triggers a retry; eventual success is returned.
* 401 does NOT retry (auth errors are permanent).
* Malformed JSON / wrong shape raises :class:`LLMResponseFormatError`.
* Timeouts raise :class:`LLMTimeoutError`.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMResponseFormatError,
    LLMTimeoutError,
)

_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_GENERIC_URL = "https://gateway.example.com/agent"


def _openai_response(text: str = "Hello, world!") -> dict[str, Any]:
    return {
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        "model": "gpt-4o-mini",
    }


def _anthropic_response(text: str = "Hello from Claude") -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 5, "output_tokens": 3},
        "model": "claude-3-5-sonnet-latest",
    }


# ---- OpenAI shape ----------------------------------------------------------


@respx.mock
async def test_http_adapter_openai_shape_happy_path() -> None:
    route = respx.post(_OPENAI_URL).mock(return_value=httpx.Response(200, json=_openai_response()))
    adapter = HttpAdapter(
        _OPENAI_URL,
        shape="openai",
        auth_headers={"Authorization": "Bearer sk-test"},
        model="gpt-4o-mini",
    )
    try:
        response = await adapter.call("Say hi")
        assert response == "Hello, world!"
        assert route.called
        request = route.calls.last.request
        body = json.loads(request.content)
        assert body["model"] == "gpt-4o-mini"
        assert body["messages"] == [{"role": "user", "content": "Say hi"}]
        assert request.headers["authorization"] == "Bearer sk-test"
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_openai_threads_session_as_user() -> None:
    respx.post(_OPENAI_URL).mock(return_value=httpx.Response(200, json=_openai_response("ok")))
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", auth_headers={"Authorization": "Bearer x"})
    try:
        await adapter.call("hello", session="sess-42")
        request = respx.calls.last.request
        body = json.loads(request.content)
        assert body["user"] == "sess-42"
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_openai_malformed_response_raises_format_error() -> None:
    respx.post(_OPENAI_URL).mock(return_value=httpx.Response(200, json={"choices": []}))
    adapter = HttpAdapter(_OPENAI_URL, shape="openai")
    try:
        with pytest.raises(LLMResponseFormatError):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_openai_invalid_json_raises_format_error() -> None:
    respx.post(_OPENAI_URL).mock(
        return_value=httpx.Response(
            200, content=b"not json", headers={"content-type": "application/json"}
        )
    )
    adapter = HttpAdapter(_OPENAI_URL, shape="openai")
    try:
        with pytest.raises(LLMResponseFormatError, match="invalid JSON"):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_openai_response_top_level_array_raises() -> None:
    respx.post(_OPENAI_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    adapter = HttpAdapter(_OPENAI_URL, shape="openai")
    try:
        with pytest.raises(LLMResponseFormatError, match="JSON object"):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


# ---- Anthropic shape -------------------------------------------------------


@respx.mock
async def test_http_adapter_anthropic_shape_happy_path() -> None:
    route = respx.post(_ANTHROPIC_URL).mock(
        return_value=httpx.Response(200, json=_anthropic_response())
    )
    adapter = HttpAdapter(
        _ANTHROPIC_URL,
        shape="anthropic",
        auth_headers={"x-api-key": "ak-test", "anthropic-version": "2023-06-01"},
        model="claude-3-5-sonnet-latest",
    )
    try:
        response = await adapter.call("Say hi")
        assert response == "Hello from Claude"
        request = route.calls.last.request
        body = json.loads(request.content)
        assert body["model"] == "claude-3-5-sonnet-latest"
        assert body["messages"] == [{"role": "user", "content": "Say hi"}]
        assert request.headers["x-api-key"] == "ak-test"
        assert request.headers["anthropic-version"] == "2023-06-01"
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_anthropic_multipart_text_concatenated() -> None:
    respx.post(_ANTHROPIC_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "part-a "},
                    {"type": "text", "text": "part-b"},
                ],
                "stop_reason": "end_turn",
                "model": "claude",
            },
        )
    )
    adapter = HttpAdapter(_ANTHROPIC_URL, shape="anthropic")
    try:
        assert await adapter.call("hi") == "part-a part-b"
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_anthropic_threads_session_into_metadata() -> None:
    respx.post(_ANTHROPIC_URL).mock(return_value=httpx.Response(200, json=_anthropic_response()))
    adapter = HttpAdapter(_ANTHROPIC_URL, shape="anthropic")
    try:
        await adapter.call("hi", session="abc")
        body = json.loads(respx.calls.last.request.content)
        assert body["metadata"] == {"user_id": "abc"}
    finally:
        await adapter.aclose()


# ---- Generic shape ---------------------------------------------------------


@respx.mock
async def test_http_adapter_generic_shape_default_template() -> None:
    respx.post(_GENERIC_URL).mock(
        return_value=httpx.Response(200, json={"output": {"text": "hello"}, "session": "s1"})
    )
    adapter = HttpAdapter(_GENERIC_URL, shape="generic")
    try:
        assert await adapter.call("hi", session="s1") == "hello"
        body = json.loads(respx.calls.last.request.content)
        assert body == {"input": "hi", "session": "s1"}
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_generic_with_custom_template_and_jsonpath() -> None:
    respx.post(_GENERIC_URL).mock(
        return_value=httpx.Response(200, json={"reply": {"data": [{"text": "templated-ok"}]}})
    )
    adapter = HttpAdapter(
        _GENERIC_URL,
        shape="generic",
        request_template='{"question": "{prompt}", "sid": "{session}"}',
        response_jsonpath="$.reply.data[0].text",
    )
    try:
        assert await adapter.call("how are you?", session="abc") == "templated-ok"
        body = json.loads(respx.calls.last.request.content)
        assert body == {"question": "how are you?", "sid": "abc"}
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_generic_template_with_quotes_in_prompt() -> None:
    respx.post(_GENERIC_URL).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    adapter = HttpAdapter(
        _GENERIC_URL,
        shape="generic",
        request_template='{"q": "{prompt}"}',
    )
    try:
        await adapter.call('he said "hi"\nthen left')
        body = json.loads(respx.calls.last.request.content)
        assert body == {"q": 'he said "hi"\nthen left'}
    finally:
        await adapter.aclose()


async def test_http_adapter_generic_invalid_template_raises() -> None:
    adapter = HttpAdapter(
        _GENERIC_URL,
        shape="generic",
        request_template="not json {prompt}",
    )
    try:
        with pytest.raises(LLMPermanentError, match="not valid JSON"):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


async def test_http_adapter_generic_template_not_object_raises() -> None:
    adapter = HttpAdapter(
        _GENERIC_URL,
        shape="generic",
        request_template='["{prompt}"]',
    )
    try:
        with pytest.raises(LLMPermanentError, match="JSON object"):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_generic_jsonpath_missing_raises_format_error() -> None:
    respx.post(_GENERIC_URL).mock(return_value=httpx.Response(200, json={"x": 1}))
    adapter = HttpAdapter(
        _GENERIC_URL,
        shape="generic",
        response_jsonpath="$.not.there",
    )
    try:
        with pytest.raises(LLMResponseFormatError, match="no value"):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


# ---- Retry / backoff behaviour ---------------------------------------------


@respx.mock
async def test_http_adapter_retries_on_429_then_succeeds() -> None:
    route = respx.post(_OPENAI_URL).mock(
        side_effect=[
            httpx.Response(429, json={"error": "slow down"}, headers={"retry-after": "0"}),
            httpx.Response(200, json=_openai_response("after-retry")),
        ]
    )
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=2)
    try:
        assert await adapter.call("hi") == "after-retry"
        assert route.call_count == 2
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_retries_on_5xx_then_succeeds() -> None:
    route = respx.post(_OPENAI_URL).mock(
        side_effect=[
            httpx.Response(503, text="server busy"),
            httpx.Response(502, text="bad gateway"),
            httpx.Response(200, json=_openai_response("finally")),
        ]
    )
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=3)
    try:
        assert await adapter.call("hi") == "finally"
        assert route.call_count == 3
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_does_not_retry_on_401() -> None:
    route = respx.post(_OPENAI_URL).mock(
        return_value=httpx.Response(401, json={"error": "bad key"})
    )
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=3)
    try:
        with pytest.raises(LLMAuthError):
            await adapter.call("hi")
        assert route.call_count == 1  # zero retries
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_does_not_retry_on_400() -> None:
    route = respx.post(_OPENAI_URL).mock(
        return_value=httpx.Response(400, json={"error": "bad request"})
    )
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=3)
    try:
        with pytest.raises(LLMPermanentError):
            await adapter.call("hi")
        assert route.call_count == 1
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_gives_up_after_max_retries() -> None:
    route = respx.post(_OPENAI_URL).mock(return_value=httpx.Response(503, text="always down"))
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=2)
    try:
        with pytest.raises(Exception) as exc_info:
            await adapter.call("hi")
        # Final exception is LLMTransientError after exhausting retries.
        from agent_guardian.llm.errors import LLMTransientError

        assert isinstance(exc_info.value, LLMTransientError)
        assert route.call_count == 3  # initial + 2 retries
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_honours_retry_after_header_value() -> None:
    """Retry-After: 0 means retry immediately; large value should still be honoured."""
    route = respx.post(_OPENAI_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "0"}),
            httpx.Response(200, json=_openai_response("ok")),
        ]
    )
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=1)
    try:
        assert await adapter.call("hi") == "ok"
        assert route.call_count == 2
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_retry_after_garbage_falls_back_to_backoff() -> None:
    route = respx.post(_OPENAI_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "tomorrow-please"}),
            httpx.Response(200, json=_openai_response("ok")),
        ]
    )
    # Make backoff effectively zero so the test stays fast.
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=1)
    try:
        # Patch the retry's sleep so we don't actually wait.
        from agent_guardian.adapters import http as http_module

        original = http_module.with_backoff

        async def _fake_with_backoff(coro_factory: Any, **_kwargs: Any) -> Any:
            return await original(
                coro_factory,
                base_seconds=0.0,
                max_retries=1,
                sleep=_noop_sleep,
            )

        http_module.with_backoff = _fake_with_backoff  # type: ignore[assignment]
        try:
            assert await adapter.call("hi") == "ok"
        finally:
            http_module.with_backoff = original  # type: ignore[assignment]
        assert route.call_count == 2
    finally:
        await adapter.aclose()


async def _noop_sleep(_seconds: float) -> None:
    return None


# ---- Timeout / network errors ----------------------------------------------


@respx.mock
async def test_http_adapter_timeout_raises_llm_timeout_error() -> None:
    respx.post(_OPENAI_URL).mock(side_effect=httpx.TimeoutException("slow"))
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=0)
    try:
        with pytest.raises(LLMTimeoutError):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_network_error_treated_as_transient() -> None:
    respx.post(_OPENAI_URL).mock(side_effect=httpx.ConnectError("no route"))
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_retries=0)
    try:
        from agent_guardian.llm.errors import LLMTransientError

        with pytest.raises(LLMTransientError):
            await adapter.call("hi")
    finally:
        await adapter.aclose()


# ---- Custom client injection ----------------------------------------------


@respx.mock
async def test_http_adapter_uses_injected_client() -> None:
    respx.post(_OPENAI_URL).mock(return_value=httpx.Response(200, json=_openai_response()))
    async with httpx.AsyncClient(timeout=5) as client:
        adapter = HttpAdapter(_OPENAI_URL, shape="openai", client=client)
        assert await adapter.call("hi") == "Hello, world!"
        # aclose must NOT close the externally-owned client.
        await adapter.aclose()
        # Client is still usable here:
        assert not client.is_closed


# ---- Concurrency-cap smoke test -------------------------------------------


@respx.mock
async def test_http_adapter_serialises_under_low_concurrency() -> None:
    """At max_concurrency=1, two parallel calls must both succeed."""
    import asyncio

    respx.post(_OPENAI_URL).mock(return_value=httpx.Response(200, json=_openai_response("ok")))
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", max_concurrency=1)
    try:
        results = await asyncio.gather(adapter.call("a"), adapter.call("b"))
        assert results == ["ok", "ok"]
    finally:
        await adapter.aclose()


# ---- Bedrock / Vertex / AgentCore still NotImplementedError ---------------


@pytest.mark.parametrize("shape", ["bedrock", "vertex", "agentcore"])
async def test_http_adapter_deferred_shapes_raise_not_implemented(shape: str) -> None:
    adapter = HttpAdapter("https://x.example.com", shape=shape)
    try:
        with pytest.raises(NotImplementedError):
            await adapter.call("hi")
    finally:
        await adapter.aclose()
