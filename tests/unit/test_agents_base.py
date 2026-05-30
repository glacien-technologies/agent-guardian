"""Unit tests for :mod:`agent_guardian.agents.base` (M7)."""

from __future__ import annotations

import json
from typing import Any

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


# ---------------------------------------------------------------------------
# #20 / #21 / #22 — _build_finding probe-corpus provenance
# ---------------------------------------------------------------------------


def _make_cascade_agent() -> Any:
    from agent_guardian.agents.cascade import CascadeAgent

    llm: StubLLM = StubScript().default("ok").build()
    return CascadeAgent(
        attacker_llm=llm,
        evaluator_llm=llm,
        attacker_model="stub",
        evaluator_model="stub",
    )


def test_build_finding_uses_synthetic_id_without_seed_metadata() -> None:
    """Back-compat: a no-metadata call falls back to the synthetic agent-name+ASI id."""
    agent = _make_cascade_agent()
    verdict = JudgeVerdict(verdict="fail", confidence=0.9, reasoning="r")
    finding = agent._build_finding(
        prompt="p",
        response="r",
        verdict=verdict,
        attempt_count=1,
        strategy_metadata=None,
    )
    # Synthetic fallback id.
    assert "cascade-agent" in finding.probe_id
    assert AsiCategory.ASI08.value in finding.probe_id
    # Severity falls back to the agent default.
    from agent_guardian.models.severity import Severity as _Sev

    assert finding.severity is _Sev.HIGH  # CascadeAgent.default_severity = HIGH


def test_build_finding_threads_seed_probe_id_through_metadata() -> None:
    """#22 — when ``strategy_metadata`` carries ``seed_id``, that probe_id is stamped on the finding."""
    from agent_guardian.models.severity import Severity as _Sev
    from agent_guardian.strategies.base import ProbeSeed

    agent = _make_cascade_agent()
    # Pre-populate the seed index as ``run()`` would.
    seed = ProbeSeed(
        probe_id="ASI08-CASCADE-007",
        text="trigger a cascading fault",
        asi=AsiCategory.ASI08.value,
        severity=_Sev.LOW.value,
    )
    agent._seed_index = {seed.probe_id: seed}

    verdict = JudgeVerdict(verdict="fail", confidence=0.9, reasoning="r")
    finding = agent._build_finding(
        prompt="p",
        response="r",
        verdict=verdict,
        attempt_count=1,
        strategy_metadata={"seed_id": "ASI08-CASCADE-007"},
    )
    assert finding.probe_id == "ASI08-CASCADE-007"
    # #21 — the probe's severity (LOW) overrides the agent's default (HIGH).
    assert finding.severity is _Sev.LOW


def test_build_finding_two_distinct_probe_ids_emit_distinct_findings() -> None:
    """Two findings from one agent driven by distinct seeds must keep their distinct probe_ids (#22)."""
    from agent_guardian.strategies.base import ProbeSeed

    agent = _make_cascade_agent()
    s1 = ProbeSeed(probe_id="ASI08-A", text="x", severity="high")
    s2 = ProbeSeed(probe_id="ASI08-B", text="y", severity="high")
    agent._seed_index = {s1.probe_id: s1, s2.probe_id: s2}

    verdict = JudgeVerdict(verdict="fail", confidence=0.9, reasoning="r")
    f1 = agent._build_finding(
        prompt="p1",
        response="r",
        verdict=verdict,
        attempt_count=1,
        strategy_metadata={"seed_id": "ASI08-A"},
    )
    f2 = agent._build_finding(
        prompt="p2",
        response="r",
        verdict=verdict,
        attempt_count=1,
        strategy_metadata={"seed_id": "ASI08-B"},
    )
    assert f1.probe_id == "ASI08-A"
    assert f2.probe_id == "ASI08-B"
    assert f1.probe_id != f2.probe_id


def test_target_findings_override_raises_per_agent_cap() -> None:
    """#20 — SwarmConfig.target_findings_per_agent surfaces as the live cap."""
    from agent_guardian.agents.cascade import CascadeAgent

    llm: StubLLM = StubScript().default("ok").build()
    agent = CascadeAgent(
        attacker_llm=llm,
        evaluator_llm=llm,
        attacker_model="stub",
        evaluator_model="stub",
        target_findings_override=20,
    )
    assert agent.effective_target_findings == 20
    # Default unchanged when no override.
    default_agent = CascadeAgent(
        attacker_llm=llm,
        evaluator_llm=llm,
        attacker_model="stub",
        evaluator_model="stub",
    )
    assert default_agent.effective_target_findings == CascadeAgent.target_findings


# ---------------------------------------------------------------------------
# #25 — Cascade runs Crescendo, not PAIR
# ---------------------------------------------------------------------------


def test_cascade_agent_strategy_stack_is_crescendo() -> None:
    """CascadeAgent.attack_specialization advertises Crescendo; the strategy must match."""
    import random as _random

    from agent_guardian.core.memory import SharedMemory
    from agent_guardian.strategies.base import StrategyContext
    from agent_guardian.strategies.crescendo import CrescendoStrategy

    agent = _make_cascade_agent()
    ctx = StrategyContext(
        attacker_llm=agent.attacker_llm,
        attacker_model="stub",
        goal="Trigger cascading failure",
        seeds=[],
        memory=SharedMemory("scan-test"),
        rng=_random.Random(0),
        max_turns=4,
    )
    strategy = agent.strategy_stack(ctx)
    assert isinstance(strategy, CrescendoStrategy)
