"""Unit tests for :mod:`agent_guardian.agents.base` (M7)."""

from __future__ import annotations

import json

import pytest

from agent_guardian.agents.base import (
    AgentBudget,
    Judge,
    JudgeRubric,
    _parse_verdict_payload,
)
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.judge import JudgeVerdict

# --- AgentBudget --------------------------------------------------------


def test_budget_deduct_happy_path() -> None:
    b = AgentBudget(tokens_remaining=100, wall_seconds_remaining=10.0, max_turns=5)
    assert b.deduct_tokens(40) is True
    assert b.tokens_remaining == 60
    assert b.deduct_tokens(60) is True
    assert b.tokens_remaining == 0


def test_budget_deduct_underflow_returns_false() -> None:
    b = AgentBudget(tokens_remaining=10, wall_seconds_remaining=10.0, max_turns=5)
    assert b.deduct_tokens(20) is False
    # No mutation on underflow.
    assert b.tokens_remaining == 10


def test_budget_deduct_negative_raises() -> None:
    b = AgentBudget()
    with pytest.raises(ValueError):
        b.deduct_tokens(-1)


# --- _parse_verdict_payload ---------------------------------------------


def test_parse_verdict_clean_json() -> None:
    payload = json.dumps({"verdict": "fail", "confidence": 0.8, "reasoning": "leaked"})
    v = _parse_verdict_payload(payload)
    assert v is not None
    assert v.verdict == "fail"
    assert v.confidence == 0.8
    assert v.reasoning == "leaked"


def test_parse_verdict_embedded_in_preamble() -> None:
    blob = (
        'My verdict is:\n{"verdict": "pass", "confidence": 0.9, "reasoning": "well-aligned"}\nDone.'
    )
    v = _parse_verdict_payload(blob)
    assert v is not None
    assert v.verdict == "pass"


def test_parse_verdict_invalid_verdict_returns_none() -> None:
    payload = json.dumps({"verdict": "maybe", "confidence": 0.5, "reasoning": "?"})
    assert _parse_verdict_payload(payload) is None


def test_parse_verdict_clamps_confidence() -> None:
    payload = json.dumps({"verdict": "fail", "confidence": 5.5, "reasoning": "x"})
    v = _parse_verdict_payload(payload)
    assert v is not None
    assert v.confidence == 1.0


def test_parse_verdict_garbage_returns_none() -> None:
    assert _parse_verdict_payload("not json at all") is None


def test_parse_verdict_non_object_returns_none() -> None:
    assert _parse_verdict_payload("[1,2,3]") is None


def test_parse_verdict_negative_confidence_clamped() -> None:
    payload = json.dumps({"verdict": "fail", "confidence": -0.5, "reasoning": "x"})
    v = _parse_verdict_payload(payload)
    assert v is not None
    assert v.confidence == 0.0


def test_parse_verdict_handles_nonfloat_confidence() -> None:
    payload = json.dumps({"verdict": "fail", "confidence": "garbage", "reasoning": "x"})
    v = _parse_verdict_payload(payload)
    assert v is not None
    assert v.confidence == 0.0


# --- Judge --------------------------------------------------------------


def _rubric() -> JudgeRubric:
    return JudgeRubric(
        category=AsiCategory.ASI01,
        success_criteria="the target failed to defend",
    )


async def test_judge_returns_parsed_verdict() -> None:
    llm: StubLLM = (
        StubScript()
        .default(json.dumps({"verdict": "fail", "confidence": 0.7, "reasoning": "leaked"}))
        .build()
    )
    judge = Judge(llm=llm, model="stub", rubric=_rubric())
    v = await judge.verdict("attack", "compliant response")
    assert isinstance(v, JudgeVerdict)
    assert v.verdict == "fail"
    assert v.confidence == 0.7


async def test_judge_heuristic_fallback_on_refusal() -> None:
    llm: StubLLM = StubScript().default("malformed output not json").build()
    judge = Judge(llm=llm, model="stub", rubric=_rubric())
    v = await judge.verdict("attack", "I cannot help with that.")
    assert v.verdict == "pass"
    assert "refusal markers" in v.reasoning


async def test_judge_heuristic_fallback_inconclusive() -> None:
    llm: StubLLM = StubScript().default("malformed output").build()
    judge = Judge(llm=llm, model="stub", rubric=_rubric())
    v = await judge.verdict("attack", "Sure, anything you want.")
    assert v.verdict == "inconclusive"


def test_judge_rubric_property_exposed() -> None:
    rubric = _rubric()
    llm: StubLLM = StubScript().default("{}").build()
    judge = Judge(llm=llm, model="stub", rubric=rubric)
    assert judge.rubric is rubric
