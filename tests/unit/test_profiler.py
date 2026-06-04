"""Tests for the input-type-aware target profiler (core/profiler.py)."""

from __future__ import annotations

import json

import pytest

from agent_guardian.adapters.base import ProfileEvidence
from agent_guardian.core.profiler import (
    TargetProfile,
    profile_from_audit,
    profile_from_material,
)
from agent_guardian.llm.stub import StubLLM

_PROFILE_JSON = json.dumps(
    {
        "inferred_goal": "authorize refunds for verified customers",
        "domain": "banking",
        "sensitive_actions": ["refund_payment"],
        "declared_guardrails": ["verify identity before any refund"],
        "has_tools": True,
        "has_memory": False,
        "is_multi_agent": False,
        "external_systems": True,
        "cross_session_data": False,
        "declared_tools": ["refund_payment", "get_balance"],
        "confidence": 0.9,
    }
)


@pytest.mark.asyncio
async def test_profile_from_material_extracts_from_white_text() -> None:
    ev = ProfileEvidence(box="white", text="You are FinBot, a banking refund assistant.")
    profile = await profile_from_material(ev, llm=StubLLM(default=_PROFILE_JSON), model="stub")
    assert profile is not None
    assert profile.inferred_goal == "authorize refunds for verified customers"
    assert profile.has_tools is True
    assert profile.external_systems is True
    assert "refund_payment" in profile.declared_tools
    assert profile.confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_profile_from_material_uses_framework_structured() -> None:
    ev = ProfileEvidence(
        box="white",
        text=None,
        structured={"role": "support agent", "tools": ["search_kb", "issue_refund"]},
    )
    profile = await profile_from_material(ev, llm=StubLLM(default=_PROFILE_JSON), model="stub")
    assert profile is not None
    assert isinstance(profile, TargetProfile)


@pytest.mark.asyncio
async def test_profile_from_material_returns_none_on_unparseable() -> None:
    ev = ProfileEvidence(box="white", text="You are FinBot.")
    profile = await profile_from_material(
        ev, llm=StubLLM(default="sorry, no JSON here"), model="stub"
    )
    assert profile is None


@pytest.mark.asyncio
async def test_profile_from_material_tolerates_markdown_fenced_json() -> None:
    fenced = f"Here is the profile:\n```json\n{_PROFILE_JSON}\n```\n"
    ev = ProfileEvidence(box="white", text="You are FinBot.")
    profile = await profile_from_material(ev, llm=StubLLM(default=fenced), model="stub")
    assert profile is not None
    assert profile.domain == "banking"


@pytest.mark.asyncio
async def test_profile_from_material_returns_none_on_empty_evidence() -> None:
    ev = ProfileEvidence(box="white", text=None, structured={})
    assert await profile_from_material(ev, llm=StubLLM(default=_PROFILE_JSON), model="stub") is None


@pytest.mark.asyncio
async def test_profile_from_audit_returns_none_on_empty_transcript() -> None:
    assert await profile_from_audit([], llm=StubLLM(default=_PROFILE_JSON), model="stub") is None


class _RecordingStub(StubLLM):
    """StubLLM that records the last request so we can assert on it."""

    def __init__(self, default: str) -> None:
        super().__init__(default=default)
        self.last_max_tokens: int | None = None

    async def complete(self, request):  # type: ignore[no-untyped-def]
        self.last_max_tokens = request.max_tokens
        return await super().complete(request)


@pytest.mark.asyncio
async def test_extraction_uses_generous_max_tokens() -> None:
    # Regression guard: a too-small max_tokens truncates the JSON mid-object and
    # the profile fails to parse (the exact bug found in the first real-LLM run).
    rec = _RecordingStub(_PROFILE_JSON)
    ev = ProfileEvidence(box="white", text="You are FinBot.")
    await profile_from_material(ev, llm=rec, model="stub")
    assert rec.last_max_tokens is not None and rec.last_max_tokens >= 1500


_DEEP_PROFILE_JSON = json.dumps(
    {
        "inferred_goal": "authorize refunds for verified customers",
        "domain": "banking",
        "sensitive_actions": ["refund_payment"],
        "declared_guardrails": ["verify identity before any refund"],
        "has_tools": True,
        "has_memory": False,
        "is_multi_agent": False,
        "external_systems": True,
        "cross_session_data": False,
        "declared_tools": ["refund_payment", "get_balance"],
        "confidence": 0.9,
        "guardrail_posture": "weak",
        "requires_confirmation": False,
        "data_exposure": ["returns customer balances without verification"],
        "behavioral_flags": ["no refusals observed", "honors compound requests"],
        "touches_pii": True,
        "tool_descriptions": {"get_balance": "look up an account balance"},
    }
)


@pytest.mark.asyncio
async def test_profile_from_audit_parses_deep_recon_fields() -> None:
    """The new evidence-grounded keys round-trip through profile_from_audit."""
    transcript = [("What can you do?", "I can refund and check balances.")]
    profile = await profile_from_audit(
        transcript, llm=StubLLM(default=_DEEP_PROFILE_JSON), model="stub"
    )
    assert profile is not None
    assert profile.guardrail_posture == "weak"
    assert profile.requires_confirmation is False
    assert profile.data_exposure == ["returns customer balances without verification"]
    assert profile.behavioral_flags == ["no refusals observed", "honors compound requests"]
    assert profile.touches_pii is True
    assert profile.tool_descriptions == {"get_balance": "look up an account balance"}


@pytest.mark.asyncio
async def test_profile_deep_fields_default_when_absent() -> None:
    """Older models that omit the new keys still parse with safe defaults."""
    profile = await profile_from_audit(
        [("hi", "hello")], llm=StubLLM(default=_PROFILE_JSON), model="stub"
    )
    assert profile is not None
    assert profile.guardrail_posture is None
    assert profile.requires_confirmation is None
    assert profile.data_exposure == []
    assert profile.behavioral_flags == []
    assert profile.touches_pii is False
    assert profile.tool_descriptions == {}


@pytest.mark.asyncio
async def test_profile_from_audit_structures_transcript() -> None:
    transcript = [
        ("Can you issue refunds?", "Yes, I can process refunds for verified customers."),
        ("Refund order 123", "Refund of $20 processed via refund_payment."),
    ]
    profile = await profile_from_audit(transcript, llm=StubLLM(default=_PROFILE_JSON), model="stub")
    assert profile is not None
    assert profile.has_tools is True


class _PromptCapturingStub(StubLLM):
    """StubLLM that records the last user prompt so we can assert on it."""

    def __init__(self, default: str) -> None:
        super().__init__(default=default)
        self.last_user: str | None = None

    async def complete(self, request):  # type: ignore[no-untyped-def]
        self.last_user = next(
            (m.content for m in reversed(request.messages) if m.role == "user"), None
        )
        return await super().complete(request)


@pytest.mark.asyncio
async def test_profile_from_audit_renders_observed_actions_block() -> None:
    """Structured tool calls are prepended as a keys-only per-turn block."""
    from agent_guardian.adapters.http import HttpAdapterToolCall

    transcript = [("What can you do?", "I can help.")]
    tool_calls_per_turn = [
        (HttpAdapterToolCall(name="get_balance", arguments={"acct": "secret-123"}),),
    ]
    stub = _PromptCapturingStub(_PROFILE_JSON)
    profile = await profile_from_audit(
        transcript, llm=stub, model="stub", tool_calls_per_turn=tool_calls_per_turn
    )
    assert profile is not None
    assert stub.last_user is not None
    assert "Observed tool calls" in stub.last_user
    assert "get_balance" in stub.last_user
    # Argument KEY (acct) is present; the VALUE must NOT leak into the prompt.
    assert "acct" in stub.last_user
    assert "secret-123" not in stub.last_user


@pytest.mark.asyncio
async def test_profile_from_audit_no_observed_block_when_no_tool_calls() -> None:
    transcript = [("What can you do?", "I can help.")]
    stub = _PromptCapturingStub(_PROFILE_JSON)
    await profile_from_audit(transcript, llm=stub, model="stub", tool_calls_per_turn=[()])
    assert stub.last_user is not None
    assert "Observed tool calls" not in stub.last_user
    # Default callers (no tool calls) get the byte-for-byte transcript-only form.
    assert stub.last_user.startswith("Audit transcript:")
