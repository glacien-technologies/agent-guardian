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


@pytest.mark.asyncio
async def test_profile_from_audit_structures_transcript() -> None:
    transcript = [
        ("Can you issue refunds?", "Yes, I can process refunds for verified customers."),
        ("Refund order 123", "Refund of $20 processed via refund_payment."),
    ]
    profile = await profile_from_audit(transcript, llm=StubLLM(default=_PROFILE_JSON), model="stub")
    assert profile is not None
    assert profile.has_tools is True
