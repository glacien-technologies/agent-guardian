"""Tests for the LLM base types."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_guardian.llm.base import (
    BaseLLM,
    LLMMessage,
    LLMRequest,
    LLMResponse,
    LLMUsage,
)


class _DummyLLM(BaseLLM):
    provider = "dummy"

    async def complete(self, request: LLMRequest) -> LLMResponse:  # pragma: no cover
        raise NotImplementedError


def test_llm_message_frozen() -> None:
    msg = LLMMessage(role="user", content="hi")
    with pytest.raises(ValidationError):
        msg.content = "x"  # type: ignore[misc]


def test_llm_message_rejects_unknown_role() -> None:
    with pytest.raises(ValidationError):
        LLMMessage(role="captain", content="ahoy")  # type: ignore[arg-type]


def test_llm_message_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        LLMMessage(role="user", content="x", extra="nope")  # type: ignore[call-arg]


def test_llm_request_defaults() -> None:
    req = LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="m")
    assert req.max_tokens == 1024
    assert req.temperature == 0.7
    assert req.seed is None
    assert req.stop is None


def test_llm_request_temperature_bounds() -> None:
    LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="m", temperature=0.0)
    LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="m", temperature=2.0)
    with pytest.raises(ValidationError):
        LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="m", temperature=-0.1)
    with pytest.raises(ValidationError):
        LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="m", temperature=2.1)


def test_llm_request_frozen() -> None:
    req = LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="m")
    with pytest.raises(ValidationError):
        req.model = "other"  # type: ignore[misc]


def test_llm_usage_non_negative() -> None:
    LLMUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0)
    with pytest.raises(ValidationError):
        LLMUsage(prompt_tokens=-1, completion_tokens=0, total_tokens=0)


def test_llm_response_finish_reason_default() -> None:
    resp = LLMResponse(
        text="ok",
        model="m",
        provider="p",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )
    assert resp.finish_reason == "stop"
    assert resp.raw is None


def test_llm_response_rejects_unknown_finish() -> None:
    with pytest.raises(ValidationError):
        LLMResponse(
            text="",
            model="m",
            provider="p",
            usage=LLMUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
            finish_reason="explode",  # type: ignore[arg-type]
        )


def test_base_llm_abstract_cannot_instantiate() -> None:
    with pytest.raises(TypeError):
        BaseLLM()  # type: ignore[abstract]


async def test_base_llm_aclose_releases_owned_client() -> None:
    llm = _DummyLLM()
    await llm.aclose()
    # idempotent
    await llm.aclose()


async def test_base_llm_context_manager() -> None:
    async with _DummyLLM() as llm:
        assert llm.provider == "dummy"


async def test_base_llm_does_not_close_external_client() -> None:
    import httpx

    client = httpx.AsyncClient()
    llm = _DummyLLM(client=client)
    await llm.aclose()
    # External client should still be open
    assert not client.is_closed
    await client.aclose()


def test_concurrency_override() -> None:
    llm = _DummyLLM(max_concurrency=42)
    assert llm._semaphore._value == 42
