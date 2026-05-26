"""Tests for OllamaClient."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import (
    LLMPermanentError,
    LLMResponseFormatError,
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


def test_ollama_concurrency_default() -> None:
    llm = OllamaClient()
    assert llm._semaphore._value == 5
