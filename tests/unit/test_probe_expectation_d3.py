"""Issue #76 (D3) — per-probe expected_safe_behavior / expected_evidence wired
from the corpus YAML -> ProbeSeed -> judge rubric -> finding."""

from __future__ import annotations

from random import Random

from agent_guardian.agents.base import AgentBudget, Judge, JudgeRubric
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.llm.base import LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.judge import JudgeVerdict
from agent_guardian.probes.loader import seeds_for_asi_with_provenance
from agent_guardian.strategies.base import ProbeSeed


def test_probeseed_carries_corpus_judging_metadata() -> None:
    """expected_evidence (was dead) + expected_safe_behavior now reach ProbeSeed."""
    seeds = seeds_for_asi_with_provenance(AsiCategory.ASI02)
    assert seeds
    # every ASI02 seed carries expected_evidence (previously dropped at the loader)
    assert all(s.expected_evidence for s in seeds)
    # the authored ASI02 batch carries expected_safe_behavior
    assert any(s.expected_safe_behavior for s in seeds)


class _CapturingLLM(StubLLM):
    def __init__(self) -> None:
        super().__init__(default="x")
        self.last_message = ""

    async def complete(self, request: LLMRequest) -> LLMResponse:  # type: ignore[override]
        self.last_message = request.messages[-1].content
        return LLMResponse(
            text='{"verdict": "defended", "refused": true, "confidence": 1.0, '
            '"observable_compromise": false, "evidence": "", "followup_probe": "", '
            '"reasoning": "ok"}',
            model=request.model,
            provider="capture",
            usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        )


async def test_verdict_folds_probe_expectation_into_rubric() -> None:
    llm = _CapturingLLM()
    judge = Judge(
        llm=llm,
        model="stub",
        rubric=JudgeRubric(category=AsiCategory.ASI02, success_criteria="category-level rule"),
    )
    await judge.verdict(
        "p",
        "r",
        probe_expectation="For THIS probe, a secure target should: refuse the unsafe argument.",
    )
    assert "category-level rule" in llm.last_message  # category rubric still there
    assert "refuse the unsafe argument" in llm.last_message  # per-probe expectation folded in


def test_build_finding_stamps_expected_safe_behavior() -> None:
    agent = PrivilegeAgent(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=20_000, wall_seconds_remaining=30.0, max_turns=5),
        rng=Random(0),
    )
    agent._seed_index = {
        "P-1": ProbeSeed(probe_id="P-1", text="x", expected_safe_behavior="require verified auth")
    }
    finding = agent._build_finding(
        prompt="p",
        response="r",
        verdict=JudgeVerdict(verdict="exploited", confidence=1.0, reasoning="x"),
        attempt_count=1,
        strategy_metadata={"seed_id": "P-1"},
    )
    assert finding.expected_safe_behavior == "require verified auth"
