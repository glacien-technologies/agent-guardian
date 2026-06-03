"""Tests for OllamaClient."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import (
    LLMPermanentError,
    LLMResponseFormatError,
    LLMTransientError,
)
from agent_guardian.llm.ollama import OllamaClient


def _req(content: str = "hi") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content=content)], model="llama3")


@respx.mock
async def test_ollama_happy_path() -> None:
    route = respx.post("http://localhost:11434/api/chat").mock(
        return_value=Response(
            200,
            json={
                "message": {"role": "assistant", "content": "hello"},
                "prompt_eval_count": 4,
                "eval_count": 2,
                "done_reason": "stop",
                "model": "llama3",
            },
        )
    )
    llm = OllamaClient()
    resp = await llm.complete(_req())
    assert resp.text == "hello"
    assert resp.provider == "ollama"
    assert resp.usage.prompt_tokens == 4
    assert resp.usage.completion_tokens == 2
    assert resp.usage.total_tokens == 6
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body["stream"] is False
    assert sent_body["options"]["num_predict"] == 1024
    await llm.aclose()


@respx.mock
async def test_ollama_seed_and_stop_propagated() -> None:
    route = respx.post("http://localhost:11434/api/chat").mock(
        return_value=Response(
            200,
            json={
                "message": {"role": "assistant", "content": "ok"},
                "prompt_eval_count": 1,
                "eval_count": 1,
                "done_reason": "stop",
                "model": "llama3",
            },
        )
    )
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="llama3",
        seed=7,
        stop=["</s>"],
    )
    llm = OllamaClient()
    await llm.complete(req)
    body = json.loads(route.calls.last.request.content)
    assert body["options"]["seed"] == 7
    assert body["options"]["stop"] == ["</s>"]
    await llm.aclose()


@respx.mock
async def test_ollama_custom_base_url() -> None:
    respx.post("http://my-ollama:8080/api/chat").mock(
        return_value=Response(
            200,
            json={
                "message": {"role": "assistant", "content": "x"},
                "prompt_eval_count": 1,
                "eval_count": 1,
                "done_reason": "stop",
            },
        )
    )
    llm = OllamaClient(base_url="http://my-ollama:8080")
    resp = await llm.complete(_req())
    assert resp.text == "x"
    await llm.aclose()


@respx.mock
async def test_ollama_finish_reason_length() -> None:
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=Response(
            200,
            json={
                "message": {"role": "assistant", "content": "..."},
                "prompt_eval_count": 1,
                "eval_count": 1,
                "done_reason": "length",
            },
        )
    )
    llm = OllamaClient()
    resp = await llm.complete(_req())
    assert resp.finish_reason == "length"
    await llm.aclose()


@respx.mock
async def test_ollama_transient_5xx_retries() -> None:
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=[
            Response(500, json={"error": "boom"}),
            Response(
                200,
                json={
                    "message": {"role": "assistant", "content": "later"},
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                    "done_reason": "stop",
                },
            ),
        ]
    )
    llm = OllamaClient()
    resp = await llm.complete(_req())
    assert resp.text == "later"
    await llm.aclose()


@respx.mock
async def test_ollama_permanent_400() -> None:
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=Response(400, json={"error": "bad model"})
    )
    llm = OllamaClient()
    with pytest.raises(LLMPermanentError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_ollama_invalid_json() -> None:
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=Response(200, content=b"not-json")
    )
    llm = OllamaClient()
    with pytest.raises(LLMResponseFormatError):
        await llm.complete(_req())
    await llm.aclose()


@respx.mock
async def test_ollama_failed_call_logs_via_helper_error_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A transport failure surfaces via the shared ``log_model_response`` error
    path — one WARNING ``model call failed:`` line carrying the cause — rather
    than an ad-hoc per-provider ``ollama network error`` line."""
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    llm = OllamaClient()
    with (
        caplog.at_level(logging.WARNING, logger="agent_guardian.llm.ollama"),
        pytest.raises(LLMTransientError),
    ):
        await llm.complete(_req())
    failed = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and r.getMessage().startswith("model call failed:")
    ]
    assert failed, [r.getMessage() for r in caplog.records]
    # The cause (exception type + message) is spelled out in the unified line.
    assert "ConnectError" in failed[0].getMessage()
    # The old ad-hoc per-provider line is gone.
    assert not [r for r in caplog.records if "ollama network error" in r.getMessage()]
    await llm.aclose()


@respx.mock
async def test_ollama_invalid_json_logs_via_helper_error_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An invalid-JSON 2xx body also routes through the helper's error path."""
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=Response(200, content=b"not-json")
    )
    llm = OllamaClient()
    with (
        caplog.at_level(logging.WARNING, logger="agent_guardian.llm.ollama"),
        pytest.raises(LLMResponseFormatError),
    ):
        await llm.complete(_req())
    failed = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and r.getMessage().startswith("model call failed:")
    ]
    assert failed, [r.getMessage() for r in caplog.records]
    await llm.aclose()


def test_ollama_concurrency_default() -> None:
    llm = OllamaClient()
    assert llm._semaphore._value == 5
