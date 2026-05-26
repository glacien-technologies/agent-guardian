"""Tests for the deterministic StubLLM."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_guardian.llm.base import LLMMessage, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.stub import StubLLM, StubScript


def _req(content: str = "hello", model: str = "stub-1") -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content=content)], model=model)


async def test_default_response_returned_when_no_match() -> None:
    llm = StubLLM()
    resp = await llm.complete(_req())
    assert resp.text == "STUB_RESPONSE"
    assert resp.provider == "stub"
    assert resp.model == "stub-1"
    assert resp.finish_reason == "stop"


async def test_custom_default() -> None:
    llm = StubLLM(default="hi-back")
    resp = await llm.complete(_req())
    assert resp.text == "hi-back"


async def test_no_default_raises() -> None:
    llm = StubLLM(canned={}, default=None)
    with pytest.raises(KeyError):
        await llm.complete(_req())


async def test_substring_match_case_insensitive() -> None:
    llm = StubLLM(canned={"PING": "pong"})
    resp = await llm.complete(_req("send a ping please"))
    assert resp.text == "pong"


async def test_longest_substring_wins() -> None:
    llm = StubLLM(
        canned={
            "hello": "short",
            "hello world": "long",
            "world": "world-only",
        }
    )
    resp = await llm.complete(_req("hello world friend"))
    assert resp.text == "long"


async def test_substring_uses_last_user_message() -> None:
    llm = StubLLM(canned={"ping": "pong", "hello": "hi"})
    req = LLMRequest(
        messages=[
            LLMMessage(role="user", content="hello"),
            LLMMessage(role="assistant", content="hi back"),
            LLMMessage(role="user", content="ping"),
        ],
        model="m",
    )
    resp = await llm.complete(req)
    assert resp.text == "pong"


async def test_substring_ignores_non_user_messages() -> None:
    llm = StubLLM(canned={"ping": "pong"}, default="fallback")
    req = LLMRequest(
        messages=[
            LLMMessage(role="system", content="ping the user"),
        ],
        model="m",
    )
    resp = await llm.complete(req)
    # No user message → no substring match → default
    assert resp.text == "fallback"


async def test_hash_match_exact() -> None:
    req = _req("specific prompt")
    digest = StubLLM.hash_request(req)
    llm = StubLLM(canned={digest: "exact-match"})
    resp = await llm.complete(req)
    assert resp.text == "exact-match"


async def test_hash_takes_precedence_over_substring() -> None:
    req = _req("hello world")
    digest = StubLLM.hash_request(req)
    llm = StubLLM(canned={digest: "from-hash", "hello": "from-substring"})
    resp = await llm.complete(req)
    assert resp.text == "from-hash"


def test_hash_request_is_deterministic() -> None:
    req = _req("x")
    assert StubLLM.hash_request(req) == StubLLM.hash_request(req)


def test_hash_request_is_field_order_independent() -> None:
    r1 = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="m",
        max_tokens=10,
        temperature=0.0,
    )
    r2 = LLMRequest(
        max_tokens=10,
        model="m",
        temperature=0.0,
        messages=[LLMMessage(role="user", content="hi")],
    )
    assert StubLLM.hash_request(r1) == StubLLM.hash_request(r2)


def test_hash_request_distinguishes_different_inputs() -> None:
    h1 = StubLLM.hash_request(_req("a"))
    h2 = StubLLM.hash_request(_req("b"))
    assert h1 != h2


async def test_canned_response_object_passes_through() -> None:
    canned = LLMResponse(
        text="hello",
        model="custom",
        provider="stub",
        usage=LLMUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
        finish_reason="length",
    )
    llm = StubLLM(canned={"hello": canned})
    resp = await llm.complete(_req("hello"))
    assert resp is canned
    assert resp.finish_reason == "length"
    assert resp.usage.total_tokens == 30


async def test_default_token_estimator() -> None:
    llm = StubLLM(default="response")
    resp = await llm.complete(_req("hello world"))
    # default estimator: len(s) // 4
    assert resp.usage.prompt_tokens == max(1, len("hello world") // 4)
    assert resp.usage.completion_tokens == max(1, len("response") // 4)
    assert resp.usage.total_tokens == resp.usage.prompt_tokens + resp.usage.completion_tokens


async def test_custom_token_estimator_is_honoured() -> None:
    llm = StubLLM(default="ok", token_count_estimator=lambda s: 99)
    resp = await llm.complete(_req("hi"))
    assert resp.usage.prompt_tokens == 99
    assert resp.usage.completion_tokens == 99


async def test_stub_aclose_is_noop() -> None:
    llm = StubLLM()
    await llm.aclose()
    # still usable
    resp = await llm.complete(_req())
    assert resp.text == "STUB_RESPONSE"


@settings(deadline=None, max_examples=50)
@given(content=st.text(min_size=0, max_size=200))
async def test_property_determinism(content: str) -> None:
    """Same LLMRequest → identical LLMResponse, every time, every run."""
    llm = StubLLM(default="determ")
    req = LLMRequest(messages=[LLMMessage(role="user", content=content)], model="m")
    a = await llm.complete(req)
    b = await llm.complete(req)
    assert a == b
    assert StubLLM.hash_request(req) == StubLLM.hash_request(req)


# --- StubScript ---------------------------------------------------------


async def test_stub_script_fluent_builder() -> None:
    llm = StubScript().respond_to("hello", "world").respond_to("ping", "pong").build()
    assert (await llm.complete(_req("hello"))).text == "world"
    assert (await llm.complete(_req("ping"))).text == "pong"


async def test_stub_script_default_override() -> None:
    llm = StubScript().respond_to("hi", "ok").default("else").build()
    assert (await llm.complete(_req("unknown"))).text == "else"


async def test_stub_script_no_default_raises() -> None:
    llm = StubScript().respond_to("hi", "ok").no_default().build()
    with pytest.raises(KeyError):
        await llm.complete(_req("nope"))


def test_stub_script_rejects_empty_substring() -> None:
    with pytest.raises(ValueError):
        StubScript().respond_to("", "x")


def test_stub_script_respond_to_hash_validates() -> None:
    with pytest.raises(ValueError):
        StubScript().respond_to_hash("not-a-hash", "x")


async def test_stub_script_respond_to_hash_works() -> None:
    req = _req("abc")
    digest = StubLLM.hash_request(req)
    llm = StubScript().respond_to_hash(digest, "matched").build()
    assert (await llm.complete(req)).text == "matched"


async def test_stub_script_token_estimator_propagates() -> None:
    llm = StubScript().default("ok").token_estimator(lambda s: 7).build()
    resp = await llm.complete(_req("hi"))
    assert resp.usage.prompt_tokens == 7
