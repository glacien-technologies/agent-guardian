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


def test_generated_turn_attaches_provenance_seed_id() -> None:
    """Issue #82 — a generated turn (no dispatched corpus seed) attaches a
    representative same-category provenance id so its probe metadata still
    reaches the judge, WITHOUT faking seed_id (no finding mis-attribution)."""
    import random
    import tempfile
    from pathlib import Path

    from agent_guardian.core.memory import SharedMemory
    from agent_guardian.strategies.base import StrategyContext
    from agent_guardian.strategies.crescendo import CrescendoStrategy

    seed = ProbeSeed(
        probe_id="ASI06-MP-001",
        text="poison memory",
        expected_safe_behavior="refuse to persist unverified policy",
    )
    ctx = StrategyContext(
        attacker_llm=StubLLM(default="x"),
        attacker_model="stub",
        goal="g",
        seeds=[seed],
        memory=SharedMemory("s82", root_dir=Path(tempfile.mkdtemp())),
        rng=random.Random(0),
    )
    meta = CrescendoStrategy(ctx)._build_seed_metadata(None)
    assert meta.get("provenance_seed_id") == "ASI06-MP-001"
    assert "seed_id" not in meta  # not mis-attributed


def test_provenance_id_none_for_raw_string_seeds() -> None:
    """Raw-string seeds carry no probe id, so no provenance is attached."""
    import random
    import tempfile
    from pathlib import Path

    from agent_guardian.core.memory import SharedMemory
    from agent_guardian.strategies.base import StrategyContext
    from agent_guardian.strategies.crescendo import CrescendoStrategy

    ctx = StrategyContext(
        attacker_llm=StubLLM(default="x"),
        attacker_model="stub",
        goal="g",
        seeds=["just a raw string seed"],
        memory=SharedMemory("s82b", root_dir=Path(tempfile.mkdtemp())),
        rng=random.Random(0),
    )
    meta = CrescendoStrategy(ctx)._build_seed_metadata(None)
    assert "provenance_seed_id" not in meta


def test_generated_turn_finding_does_not_borrow_category_remediation() -> None:
    """Issue #137 (supersedes #82) — a generated-turn finding (no dispatched
    seed_id, only a provenance_seed_id) must NOT borrow the nominal category's
    expected_safe_behavior. That category-"representative" remediation can
    describe a different attack class than the finding's actual evidence (e.g.
    an ASI09 balance-disclosure finding carrying "XSS/canary" advice), telling
    the user to fix the wrong thing. With no matched probe, the field is None."""
    from agent_guardian.agents.base import AgentBudget
    from agent_guardian.agents.privilege import PrivilegeAgent

    agent = PrivilegeAgent(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=20_000, wall_seconds_remaining=30.0, max_turns=5),
        rng=Random(0),
    )
    agent._seed_index = {
        "ASI06-MP-001": ProbeSeed(
            probe_id="ASI06-MP-001", text="x", expected_safe_behavior="refuse unverified policy"
        )
    }
    finding = agent._build_finding(
        prompt="p",
        response="r",
        verdict=JudgeVerdict(verdict="exploited", confidence=1.0, reasoning="x"),
        attempt_count=1,
        strategy_metadata={"provenance_seed_id": "ASI06-MP-001"},  # generated turn, no seed_id
    )
    # #137: remediation is no longer borrowed from the category-representative seed
    assert finding.expected_safe_behavior is None
    # probe_id is still not faked to the provenance probe (attribution stays synthetic)
    assert finding.probe_id != "ASI06-MP-001"
