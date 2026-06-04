"""Regression tests for the empty-plan / zero-agent silent gate-pass bug.

The bug chain (P1):

1. ``SwarmCommander._build_completeness`` reported ``pct=100.0`` when
   ``turns_planned == 0`` (zero agents launched), so the completeness gate
   in :meth:`_phase_finalise` never fired.
2. ``compute_aivss`` then ran ``_tier_weighted_aggregate_excluding`` with
   every category excluded (no findings, no never_launched signals from a
   live scan), which fell back to ``return 100.0`` when the denominator
   collapsed to zero.
3. The composed result was a 100/EXCELLENT verdict for a scan that tested
   nothing.

These regression tests pin every link of that chain so the bug cannot
silently regress. The end-to-end test drives ``_phase_finalise`` with
``_active_agents = []`` and asserts the band is ``NOT_EVALUATED``.
"""

from __future__ import annotations

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentReport
from agent_guardian.core.scoring import (
    _tier_weighted_aggregate_excluding,
    compute_aivss,
)
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier


class _FakeRealLLM(BaseLLM):
    """Non-stub LLM client so ``_detect_evaluation_mode`` returns real/True."""

    provider = "openai"

    def __init__(self) -> None:
        super().__init__(owns_client=False)

    async def complete(self, request: LLMRequest) -> LLMResponse:  # pragma: no cover
        return LLMResponse(
            text="{}",
            model=request.model,
            provider="openai",
            usage=LLMUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        )

    async def aclose(self) -> None:  # pragma: no cover
        return None


def _commander() -> SwarmCommander:
    target = PromptAdapter("t", llm=StubScript().default("ok").build(), model="stub", ref="t")
    return SwarmCommander(
        config=SwarmConfig(
            scan_id="empty-plan",
            attacker_model="openai:gpt-4o",
            evaluator_model="openai:gpt-4o",
            commander_model="anthropic:claude",
        ),
        target=target,
        attacker_llm=_FakeRealLLM(),
        evaluator_llm=_FakeRealLLM(),
        commander_llm=StubLLM(default="ok"),
    )


def test_build_completeness_zero_planned_is_zero_pct_not_hundred() -> None:
    """An empty plan (no active agents) reports 0% complete, never 100%.

    Regression for the empty-plan completeness fallback (#item-1 step 1):
    the old ``else 100.0`` caused a zero-agent scan to read as fully
    complete, defeating the completeness gate downstream.
    """
    cmd = _commander()
    cmd._agent_reports = []
    cmd._active_agents = []
    completeness = cmd._build_completeness()
    assert completeness.agents_planned == 0
    assert completeness.turns_planned == 0
    assert completeness.turns_used == 0
    assert completeness.pct == 0.0


def _report(agent: str, terminated_by: str, turns: int) -> AgentReport:
    return AgentReport(
        agent=agent,
        asi_category=None,
        findings_count=0,
        turns=turns,
        duration_seconds=0.0,
        terminated_by=terminated_by,  # type: ignore[arg-type]
    )


def test_build_completeness_corpus_exhausted_reads_full() -> None:
    """Agents that ran their whole (small) probe corpus count as 100% complete.

    Regression for the phantom-denominator bug: probe corpora per ASI category
    are far smaller than ``max_turns_per_agent``, so a fully-run, uncapped scan
    used to read ~50% via ``turns_used / (agents * 12)`` and have its
    ``--mode full`` grade withheld. Corpus-exhausted (or succeeded) agents now
    count as complete, so the authoritative gate is actually reachable.
    """
    cmd = _commander()
    cmd._active_agents = [object()] * 4  # type: ignore[list-item]  # only len() matters
    cmd._agent_reports = [
        _report("identity-leak-agent", "exhausted", 2),
        _report("secret-extraction-agent", "success", 3),
        _report("drift-agent", "exhausted", 5),
        _report("fuzzing-agent", "exhausted", 12),
    ]
    c = cmd._build_completeness()
    assert c.agents_planned == 4
    assert c.agents_completed == 4
    assert c.agents_cut_short == 0
    # 100% complete -- NOT the old 22/(4*12)=45.8% turns-based reading.
    assert c.pct == 100.0
    # turns_used / turns_planned retained as informational detail.
    assert c.turns_used == 22
    assert c.turns_planned == 4 * (cmd.config.max_turns_per_agent or 12)


def test_build_completeness_framework_cut_short_reduces_pct() -> None:
    """Only framework-truncated agents (cancelled / budget / error) lower it."""
    cmd = _commander()
    cmd._active_agents = [object()] * 4  # type: ignore[list-item]  # only len() matters
    cmd._agent_reports = [
        _report("a", "exhausted", 4),
        _report("b", "success", 3),
        _report("c", "cancelled", 6),  # early-stopped mid-run
        _report("d", "budget", 5),  # budget-truncated mid-corpus
    ]
    c = cmd._build_completeness()
    assert c.agents_completed == 2
    assert c.agents_cut_short == 2
    assert c.pct == 50.0  # 2 of 4 applicable agents finished


def test_tier_aggregate_excluding_all_categories_returns_zero() -> None:
    """All categories excluded -> aggregate is 0.0, not 100.0.

    Regression for the tier-aggregate fallback (#item-1 step 2): the old
    fallback returned 100.0 when every weight was excluded.
    """
    scores = dict.fromkeys(AsiCategory, 100.0)
    aggregate = _tier_weighted_aggregate_excluding(scores, Tier.T2_HIGH, exclude=set(AsiCategory))
    assert aggregate == 0.0


def test_compute_aivss_with_full_never_launched_set_is_grade_f() -> None:
    """Every category never_launched -> coverage_grade F + score 0.

    The two fallback fixes compose: the aggregate falls to 0.0 AND the
    coverage grade reflects that nothing ran.
    """
    result = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        never_launched=set(AsiCategory),
    )
    assert result.score == 0
    assert result.coverage_grade == "F"
    assert result.band not in {SeverityBand.GOOD, SeverityBand.EXCELLENT}


@pytest.mark.asyncio
async def test_phase_finalise_empty_active_agents_is_not_evaluated() -> None:
    """End-to-end: ``_active_agents=[]`` produces ``band=NOT_EVALUATED``.

    Drives ``_phase_finalise`` with a real (non-stub) LLM pair so the
    only way the band can land on NOT_EVALUATED is through the
    completeness gate firing on the empty plan (a stub run already routes
    to NOT_EVALUATED via :meth:`_detect_evaluation_mode`).
    """
    cmd = _commander()
    # Empty plan: no agent ever launched, no reports were generated.
    cmd._active_agents = []
    cmd._agent_reports = []
    cmd._start_time = 0.0
    scan = await cmd._phase_finalise()
    # The completeness gate must refuse to claim authoritativeness.
    assert scan.band is SeverityBand.NOT_EVALUATED, (
        f"empty plan must produce NOT_EVALUATED; got band={scan.band!r} "
        f"aivss={scan.aivss} mode_authoritative={scan.mode_authoritative}"
    )
    assert scan.scoring_valid is False
    assert scan.mode_authoritative is False
    # The numeric score is preserved for debugging but must NOT lift the
    # band — and with all categories defaulting to 100 with the old bug,
    # the aggregate would have been 100. After the fix the gate fires
    # regardless of the underlying number.
    assert scan.completeness is not None
    assert scan.completeness.pct == 0.0


@pytest.mark.asyncio
async def test_phase_finalise_empty_plan_coverage_grade_is_a_but_gate_fires() -> None:
    """An empty plan has no launched/no-finding categories, so the
    coverage_grade computation lands on ``A`` (no impacted categories) -- the
    completeness gate is the one that must catch this case.

    This pins the contract: even if a future change tightened the
    coverage_grade definition to be stricter, the completeness gate still
    must refuse to gate-pass on the empty plan.
    """
    cmd = _commander()
    cmd._active_agents = []
    cmd._agent_reports = []
    cmd._start_time = 0.0
    scan = await cmd._phase_finalise()
    # band gate fired -> NOT_EVALUATED regardless of the coverage_grade value.
    assert scan.band is SeverityBand.NOT_EVALUATED
    # coverage_grade is persisted on the Scan.
    assert scan.coverage_grade in {"A", "B", "C", "D", "F"}


def test_coverage_grade_d_or_f_forces_scoring_invalid_in_compute_aivss() -> None:
    """When 5+ categories are never_launched, coverage_grade is D/F.

    The swarm's completeness gate consumes this to force
    ``scoring_valid=False``. We pin the underlying invariant that the
    grade itself does become D/F as the slate empties.
    """
    # 5 of 10 = grade D.
    five = {
        AsiCategory.ASI01,
        AsiCategory.ASI02,
        AsiCategory.ASI03,
        AsiCategory.ASI04,
        AsiCategory.ASI05,
    }
    result = compute_aivss(findings=[], probes=[], tier=Tier.T2_HIGH, never_launched=five)
    assert result.coverage_grade == "D"
    # 6 of 10 = grade F.
    six = five | {AsiCategory.ASI06}
    result_f = compute_aivss(findings=[], probes=[], tier=Tier.T2_HIGH, never_launched=six)
    assert result_f.coverage_grade == "F"
