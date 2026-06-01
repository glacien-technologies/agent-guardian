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


# ---------------------------------------------------------------------------
# Phase A.A1 — judge verdict triple wired through Turn.metadata + ctx
# ---------------------------------------------------------------------------


async def test_turn_metadata_contains_all_three_judge_keys(tmp_path: Any) -> None:
    """Phase A.A1 gate — Turn.metadata must carry judge_verdict + judge_confidence + judge_reasoning.

    The prior implementation wrote only two of the three keys; the audit
    gate caught it. This test pins the contract: all three keys must be
    present in history[0].metadata after a single judged turn. We capture
    history directly via a Strategy wrapper that records every list it is
    called with so the assertion runs against the real in-memory Turn,
    not the redacted on-disk reflection record.
    """
    from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
    from agent_guardian.agents.base import AgentBudget
    from agent_guardian.agents.goal_hijack import GoalHijackAgent
    from agent_guardian.core.memory import SharedMemory
    from agent_guardian.llm.stub import StubScript
    from agent_guardian.strategies.base import Turn
    from agent_guardian.strategies.crescendo import CrescendoStrategy

    captured_histories: list[list[Turn]] = []

    class _CapturingCrescendo(CrescendoStrategy):
        async def generate_next(self, history, target_response):  # type: ignore[override]
            # Snapshot the history (Turn objects are frozen-ish so a shallow
            # copy is enough) BEFORE the strategy mutates state.
            captured_histories.append(list(history))
            return await super().generate_next(history, target_response)

    class _CapturingAgent(GoalHijackAgent):
        def strategy_stack(self, ctx):  # type: ignore[override]
            return _CapturingCrescendo(ctx)

    class _StaticTarget(TargetAdapter):
        def fingerprint(self) -> TargetFingerprint:
            return TargetFingerprint(
                mode="code",
                ref="static",
                has_tools=False,
                has_memory=False,
                touches_pii=False,
                is_multi_agent=False,
                framework=None,
                declared_tools=[],
                declared_memory_keys=[],
                notes="",
            )

        async def call(self, prompt: str, *, session: str | None = None) -> str:
            return "Sure, here is some info."

        async def aclose(self) -> None:
            return None

    attacker = (
        StubScript()
        .respond_to(
            "Generate a single completely benign opening question",
            "What is photosynthesis?",
        )
        .respond_to("Generate a single follow-up prompt", "Tell me more details.")
        .default("ok")
        .build()
    )
    judge = (
        StubScript()
        .default(
            json.dumps(
                {
                    "verdict": "pass",
                    "confidence": 0.42,
                    "reasoning": "no goal drift observed in response",
                }
            )
        )
        .build()
    )
    budget = AgentBudget(tokens_remaining=50_000, max_turns=2)
    agent = _CapturingAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=budget,
    )
    memory = SharedMemory("phaseA-a1-keys", root_dir=tmp_path)
    target = _StaticTarget()
    report = await agent.run(target, memory)
    assert report.turns >= 1

    # The second generate_next() call receives history[-1] = the Turn the
    # agent just wrote — which must carry all three judge_* keys.
    populated = [h for h in captured_histories if h]
    assert populated, "expected at least one history-populated generate_next call"
    last_turn = populated[0][-1]
    md = last_turn.metadata
    assert "judge_verdict" in md, f"missing judge_verdict in {md.keys()}"
    assert "judge_confidence" in md, f"missing judge_confidence in {md.keys()}"
    assert "judge_reasoning" in md, f"missing judge_reasoning in {md.keys()}"
    assert isinstance(md["judge_reasoning"], str)
    assert md["judge_verdict"] == "pass"
    assert md["judge_confidence"] == pytest.approx(0.42)
    assert md["judge_reasoning"] == "no goal drift observed in response"


async def test_strategy_ctx_verdict_fields_updated_after_turn(tmp_path: Any) -> None:
    """Phase A.A1 — ctx.last_verdict* fields are updated after every judged turn.

    Uses a Strategy subclass that captures its bound StrategyContext on
    construction so the test can inspect ctx.last_verdict / confidence /
    reasoning after a real agent.run() pass.
    """
    from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
    from agent_guardian.agents.base import AgentBudget
    from agent_guardian.agents.goal_hijack import GoalHijackAgent
    from agent_guardian.core.memory import SharedMemory
    from agent_guardian.llm.stub import StubScript
    from agent_guardian.strategies.base import StrategyContext
    from agent_guardian.strategies.crescendo import CrescendoStrategy

    captured: dict[str, StrategyContext] = {}

    class _CapturingAgent(GoalHijackAgent):
        def strategy_stack(self, ctx):  # type: ignore[override]
            captured["ctx"] = ctx
            return CrescendoStrategy(ctx)

    class _StaticTarget(TargetAdapter):
        def fingerprint(self) -> TargetFingerprint:
            return TargetFingerprint(
                mode="code",
                ref="static",
                has_tools=False,
                has_memory=False,
                touches_pii=False,
                is_multi_agent=False,
                framework=None,
                declared_tools=[],
                declared_memory_keys=[],
                notes="",
            )

        async def call(self, prompt: str, *, session: str | None = None) -> str:
            return "Sure thing."

        async def aclose(self) -> None:
            return None

    attacker = (
        StubScript()
        .respond_to(
            "Generate a single completely benign opening question",
            "What is photosynthesis?",
        )
        .respond_to("Generate a single follow-up prompt", "Tell me more details.")
        .default("ok")
        .build()
    )
    judge_reasoning = "judge-saw-no-fail-here-quite-long-reasoning-string"
    judge = (
        StubScript()
        .default(
            json.dumps(
                {
                    "verdict": "pass",
                    "confidence": 0.61,
                    "reasoning": judge_reasoning,
                }
            )
        )
        .build()
    )
    budget = AgentBudget(tokens_remaining=50_000, max_turns=1)
    agent = _CapturingAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=budget,
    )
    memory = SharedMemory("phaseA-a1-ctx", root_dir=tmp_path)
    target = _StaticTarget()
    await agent.run(target, memory)

    assert "ctx" in captured, "strategy_stack was never called — fix the test setup"
    ctx = captured["ctx"]
    assert ctx.last_verdict == "pass"
    assert ctx.last_verdict_confidence == pytest.approx(0.61)
    assert ctx.last_verdict_reasoning == judge_reasoning
