"""Runtime USD budget cap: live meter, 80% soft-stop watchdog, finalise
hard-ceiling, and the report's stopped_reason / budget / completeness blocks.

These replace the old pre-flight ``estimate_scan_cost`` gate (which was
mode-blind and over-estimated by ~46x). The cap is now metered against
*actual* spend.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.budget import tokens_to_usd
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm.base import LLMRequest, LLMResponse
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity

_FLASH = "gemini-2.5-flash"


def _finding(fid: str, *, trigger: str | None = "do the forbidden thing") -> Finding:
    return Finding(
        id=fid,
        probe_id="p1",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success=True,
        confidence=0.9,
        summary=f"summary {fid}",
        trigger_prompt=trigger,
        created_at=datetime(2026, 5, 28, 12, 0, 0, tzinfo=timezone.utc),
    )


def _swarm(
    usd_cap: float | None = None, checkpoint_interval_seconds: float = 30.0
) -> SwarmCommander:
    target = PromptAdapter("you are a test target", llm=StubLLM(default="ok"), model="stub")
    return SwarmCommander(
        config=SwarmConfig(
            scan_id="budget-test",
            attacker_model=_FLASH,
            evaluator_model=_FLASH,
            commander_model=_FLASH,
            usd_cap=usd_cap,
            checkpoint_interval_seconds=checkpoint_interval_seconds,
        ),
        target=target,
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
    )


# completion-token counts that price (via gemini-flash $2.5/1M output) to a
# known USD figure: tokens / 1e6 * 2.5.
def _commander_spend(swarm: SwarmCommander, usd: float) -> None:
    swarm._commander_usage.prompt_tokens = 0
    swarm._commander_usage.completion_tokens = round(usd / 2.5 * 1_000_000)


def _agent(swarm: SwarmCommander) -> GoalHijackAgent:
    return GoalHijackAgent(
        attacker_llm=swarm.attacker_llm,
        evaluator_llm=swarm.evaluator_llm,
        attacker_model=_FLASH,
        evaluator_model=_FLASH,
    )


def test_live_cost_usd_sums_priced_commander_and_agent_counters() -> None:
    swarm = _swarm()
    swarm._commander_usage.prompt_tokens = 1_000
    swarm._commander_usage.completion_tokens = 2_000

    agent = _agent(swarm)
    agent._attacker_usage.prompt_tokens = 10_000
    agent._attacker_usage.completion_tokens = 20_000
    agent._evaluator_usage.prompt_tokens = 5_000
    agent._evaluator_usage.completion_tokens = 1_000
    swarm._active_agents = [agent]

    expected = (
        tokens_to_usd(_FLASH, 1_000, 2_000)  # commander
        + tokens_to_usd(_FLASH, 10_000, 20_000)  # agent attacker
        + tokens_to_usd(_FLASH, 5_000, 1_000)  # agent evaluator
    )
    assert swarm._live_cost_usd() == pytest.approx(expected)


def test_live_cost_usd_is_zero_with_no_spend() -> None:
    swarm = _swarm()
    assert swarm._live_cost_usd() == pytest.approx(0.0)


# --------------------------------------------------------------------- watchdog


def test_soft_stop_never_trips_without_a_cap() -> None:
    swarm = _swarm(usd_cap=None)
    _commander_spend(swarm, 1_000.0)  # spend a fortune
    assert swarm._budget_soft_stop_tripped() is False


def test_soft_stop_not_tripped_below_80_percent() -> None:
    swarm = _swarm(usd_cap=1.0)
    _commander_spend(swarm, 0.75)  # 75% of cap
    assert swarm._budget_soft_stop_tripped() is False


def test_soft_stop_trips_at_or_above_80_percent() -> None:
    swarm = _swarm(usd_cap=1.0)
    _commander_spend(swarm, 0.85)  # 85% of cap
    assert swarm._budget_soft_stop_tripped() is True


@pytest.mark.asyncio
async def test_checkpoint_loop_cancels_on_budget() -> None:
    swarm = _swarm(usd_cap=1.0, checkpoint_interval_seconds=0.01)
    _commander_spend(swarm, 0.90)  # over the 80% soft-stop line
    await swarm._checkpoint_loop()
    assert swarm._cancel_event.is_set()
    assert swarm._stopped_reason == "budget"


# ------------------------------------------------------------- finalise ceiling


def test_live_cost_includes_finalise_usage() -> None:
    swarm = _swarm()
    swarm._finalise_usage.prompt_tokens = 4_000
    swarm._finalise_usage.completion_tokens = 8_000
    assert swarm._live_cost_usd() == pytest.approx(tokens_to_usd(_FLASH, 4_000, 8_000))


@pytest.mark.asyncio
async def test_finalise_judge_calls_are_metered() -> None:
    swarm = _swarm()
    judge = swarm._make_semantic_judge()
    await judge("the target leaked the secret code", "the secret was disclosed")
    assert swarm._finalise_usage.calls == 1


@pytest.mark.asyncio
async def test_finalise_truncates_paid_work_when_over_cap() -> None:
    swarm = _swarm(usd_cap=1.0)
    # Simulate the attack phase + finalise having already consumed the full cap.
    _commander_spend(swarm, 1.0)  # 100% of cap
    findings = [_finding("f1"), _finding("f2")]
    result = await swarm._apply_pov_gate(findings)
    # Over the hard ceiling -> no paid gating: findings kept exactly as-is.
    assert swarm._finalise_truncated is True
    assert result == findings


@pytest.mark.asyncio
async def test_finalise_not_truncated_under_cap() -> None:
    swarm = _swarm(usd_cap=100.0)  # generous; nowhere near the ceiling
    _commander_spend(swarm, 0.01)
    await swarm._apply_pov_gate([_finding("f1")])
    assert swarm._finalise_truncated is False


# ----------------------------------------------------------------- report blocks


def test_build_budget_report_uncapped_still_reports_spend() -> None:
    swarm = _swarm(usd_cap=None)
    _commander_spend(swarm, 0.5)
    report = swarm._build_budget_report()
    assert report.cap_usd is None
    assert report.spent_usd == pytest.approx(0.5)
    assert report.pct_of_cap is None


def test_build_budget_report_with_cap() -> None:
    swarm = _swarm(usd_cap=2.0)
    _commander_spend(swarm, 0.5)
    report = swarm._build_budget_report()
    assert report.cap_usd == pytest.approx(2.0)
    assert report.spent_usd == pytest.approx(0.5)
    assert report.pct_of_cap == pytest.approx(0.25)
    assert report.soft_stop_fraction == pytest.approx(0.80)


def test_build_completeness_counts_agents_and_turns() -> None:
    from agent_guardian.agents.base import AgentReport

    swarm = _swarm()
    swarm._active_agents = [_agent(swarm), _agent(swarm)]  # planned = 2
    swarm._agent_reports = [
        AgentReport(
            agent="recon-agent",
            asi_category=AsiCategory.ASI01,
            findings_count=0,
            turns=1,
            duration_seconds=0.1,
            terminated_by="exhausted",
        ),
        AgentReport(
            agent="goal-hijack-agent",
            asi_category=AsiCategory.ASI01,
            findings_count=0,
            turns=5,
            duration_seconds=0.1,
            terminated_by="exhausted",
        ),
        AgentReport(
            agent="tool-abuse-agent",
            asi_category=AsiCategory.ASI02,
            findings_count=0,
            turns=2,
            duration_seconds=0.1,
            terminated_by="cancelled",
        ),
    ]
    c = swarm._build_completeness()
    assert c.agents_planned == 2
    assert c.agents_completed == 1  # goal-hijack finished; recon excluded
    assert c.agents_cut_short == 1  # tool-abuse cancelled
    assert c.turns_used == 7  # 5 + 2 (recon's turn excluded)
    # pct is turns-based: turns_used / turns_planned (2 agents * 12 max-turns).
    assert c.turns_planned == 24
    assert c.pct == pytest.approx(round(7 / 24 * 100, 1))


def test_scan_model_defaults_are_backcompat() -> None:
    # A Scan built without the new fields still constructs (frozen fixtures
    # predating the budget work must keep deserialising).
    from datetime import datetime, timezone

    from agent_guardian._version import __version__ as _v
    from agent_guardian.models.scan import Scan
    from agent_guardian.models.severity import SeverityBand
    from agent_guardian.models.tier import Tier

    scan = Scan(
        id="s1",
        package_version=_v,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="ref",
        tier=Tier.T2_HIGH,
        aivss=100,
        band=SeverityBand.EXCELLENT,
        sub_scores={},
        findings=[],
        asi_scores={},
        duration_seconds=1.0,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 28, tzinfo=timezone.utc),
    )
    assert scan.stopped_reason == "completed"
    assert scan.budget is None
    assert scan.completeness is None


def test_emit_json_includes_budget_and_completeness_blocks() -> None:
    from agent_guardian._version import __version__ as _v
    from agent_guardian.models.scan import BudgetReport, Scan, ScanCompleteness
    from agent_guardian.models.severity import SeverityBand
    from agent_guardian.models.tier import Tier
    from agent_guardian.reports.json_report import emit_json

    scan = Scan(
        id="s1",
        package_version=_v,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="ref",
        tier=Tier.T2_HIGH,
        aivss=72,
        band=SeverityBand.GOOD,
        sub_scores={},
        findings=[],
        asi_scores={},
        duration_seconds=1.0,
        cost_usd=0.009,
        stopped_reason="budget",
        budget=BudgetReport(cap_usd=0.01, spent_usd=0.009, pct_of_cap=0.9, finalise_truncated=True),
        completeness=ScanCompleteness(
            agents_planned=10,
            agents_completed=7,
            agents_cut_short=3,
            turns_used=40,
            turns_planned=120,
            pct=70.0,
        ),
        created_at=datetime(2026, 5, 28, tzinfo=timezone.utc),
    )
    payload = emit_json(scan, sign=False, redact_pii=False)
    assert payload["stopped_reason"] == "budget"
    assert payload["budget"]["cap_usd"] == pytest.approx(0.01)
    assert payload["budget"]["finalise_truncated"] is True
    assert payload["completeness"]["pct"] == pytest.approx(70.0)
    assert payload["completeness"]["agents_cut_short"] == 3


# ----------------------------------------------------------- end-to-end scenarios


class _SlowStub(StubLLM):
    """StubLLM that sleeps per call so a fast checkpoint loop fires mid-scan."""

    async def complete(self, request: LLMRequest) -> LLMResponse:
        await asyncio.sleep(0.03)
        return await super().complete(request)


@pytest.mark.asyncio
async def test_full_stub_scan_uncapped_completes_with_report_blocks() -> None:
    swarm = _swarm()  # usd_cap=None
    scan = await swarm.run()
    assert scan.stopped_reason == "completed"
    assert scan.budget is not None
    assert scan.budget.cap_usd is None  # uncapped, but spend still reported
    assert scan.budget.finalise_truncated is False
    assert scan.completeness is not None
    assert scan.completeness.agents_planned >= 1
    # FULL mode (the default) suppresses early-stop, so every applicable agent
    # runs to completion -- nothing cut short, and real attack turns executed.
    assert scan.completeness.agents_cut_short == 0
    assert scan.completeness.agents_completed == scan.completeness.agents_planned
    assert scan.completeness.turns_used > 0  # pct is turns-based; stub agents
    assert scan.completeness.pct > 0.0  # may stop before max-turns, so < 100 is fine


@pytest.mark.asyncio
async def test_full_stub_scan_budget_stop_yields_partial_report() -> None:
    from agent_guardian.core.swarm import ScanMode

    target = PromptAdapter("you are a test target", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="budget-stop",
            attacker_model=_FLASH,
            evaluator_model=_FLASH,
            commander_model=_FLASH,
            mode=ScanMode.FULL,  # long enough that the watchdog fires
            usd_cap=1e-6,  # trips on the first metered tokens
            checkpoint_interval_seconds=0.005,
        ),
        target=target,
        attacker_llm=_SlowStub(default="ok"),
        evaluator_llm=_SlowStub(default="ok"),
    )
    scan = await swarm.run()
    assert scan.stopped_reason == "budget"
    assert scan.budget is not None and scan.budget.cap_usd == pytest.approx(1e-6)
    assert scan.completeness is not None
    # Budget stop cancels in-flight / not-yet-started agents -> partial coverage.
    assert scan.completeness.agents_cut_short >= 1
    assert scan.completeness.pct < 100.0
