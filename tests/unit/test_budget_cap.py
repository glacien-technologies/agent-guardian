"""Runtime USD budget cap: live meter, 80% soft-stop watchdog, finalise
hard-ceiling, and the report's stopped_reason / budget / completeness blocks.

These replace the old pre-flight ``estimate_scan_cost`` gate (which was
mode-blind and over-estimated by ~46x). The cap is now metered against
*actual* spend.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentReport
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.budget import BudgetExhausted, tokens_to_usd
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.cost import token_cost_usd
from agent_guardian.llm.base import BaseLLM, LLMMessage, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.budget_admission import admission_reservation_usd
from agent_guardian.llm.stub import StubLLM
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM
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
        created_at=datetime(2026, 5, 28, 12, 0, 0, tzinfo=UTC),
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


class _BlockingPaidLLM(BaseLLM):
    """Provider double that holds admitted calls open during admission."""

    provider = "gemini"

    def __init__(self) -> None:
        super().__init__(owns_client=False)
        self.calls = 0
        self.release = asyncio.Event()

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        await self.release.wait()
        input_tokens = sum(len(message.content) for message in request.messages)
        usage = LLMUsage(
            prompt_tokens=input_tokens,
            completion_tokens=request.max_tokens,
            total_tokens=input_tokens + request.max_tokens,
        )
        return LLMResponse(
            text="ok",
            model=request.model,
            provider=self.provider,
            usage=usage,
        )


class _FixedUsageLLM(BaseLLM):
    """Provider double with deterministic response usage per request."""

    provider = "gemini"

    def __init__(self, *, prompt_tokens: int, completion_tokens: int) -> None:
        super().__init__(owns_client=False)
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens

    async def complete(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            text='{"verdict":"pass","confidence":0.9,"reasoning":"ok"}',
            model=request.model,
            provider=self.provider,
            usage=LLMUsage(
                prompt_tokens=self.prompt_tokens,
                completion_tokens=self.completion_tokens,
                total_tokens=self.prompt_tokens + self.completion_tokens,
            ),
        )


@pytest.mark.asyncio
async def test_concurrent_paid_calls_reserve_before_provider_dispatch() -> None:
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="x" * 1_000)],
        model=_FLASH,
        max_tokens=1_000,
    )
    per_call_ceiling = admission_reservation_usd(_FLASH, 1_068, 1_000)
    cap = per_call_ceiling * 2.2
    inner = _BlockingPaidLLM()
    target = PromptAdapter("you are a test target", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="concurrent-admission",
            attacker_model=_FLASH,
            evaluator_model=_FLASH,
            commander_model=_FLASH,
            usd_cap=cap,
        ),
        target=target,
        attacker_llm=inner,
        evaluator_llm=StubLLM(default="ok"),
    )

    tasks = [asyncio.create_task(swarm.attacker_llm.complete(request)) for _ in range(3)]
    for _ in range(100):
        if inner.calls == 3 or any(task.done() for task in tasks):
            break
        await asyncio.sleep(0)

    assert inner.calls == 2
    assert swarm._stopped_reason == "budget"
    assert swarm._budget_ledger is not None
    assert swarm._budget_ledger.committed_plus_reserved_usd <= cap
    assert (
        sum(entry.usd for entry in swarm._budget_ledger.entries() if entry.kind == "reserve") <= cap
    )

    inner.release.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert sum(isinstance(result, BudgetExhausted) for result in results) == 1
    assert inner.calls == 2


@pytest.mark.asyncio
async def test_all_paid_swarm_roles_share_one_admission_ledger() -> None:
    request = LLMRequest(
        messages=[LLMMessage(role="user", content="x" * 1_000)],
        model=_FLASH,
        max_tokens=1_000,
    )
    cap = admission_reservation_usd(_FLASH, 1_068, 1_000) * 1.2
    attacker = _BlockingPaidLLM()
    evaluator = _BlockingPaidLLM()
    commander = _BlockingPaidLLM()
    target = PromptAdapter("you are a test target", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="shared-admission",
            attacker_model=_FLASH,
            evaluator_model=_FLASH,
            commander_model=_FLASH,
            usd_cap=cap,
        ),
        target=target,
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        commander_llm=commander,
    )

    tasks = [
        asyncio.create_task(swarm.attacker_llm.complete(request)),
        asyncio.create_task(swarm.evaluator_llm.complete(request)),
        asyncio.create_task(swarm.commander_llm.complete(request)),
        asyncio.create_task(swarm._finalise_evaluator_llm.complete(request)),
    ]
    for _ in range(100):
        if (
            sum(inner.calls for inner in (attacker, evaluator, commander)) == 1
            and sum(task.done() for task in tasks) == 3
        ):
            break
        await asyncio.sleep(0)

    assert sum(inner.calls for inner in (attacker, evaluator, commander)) == 1
    assert swarm._stopped_reason == "budget"
    assert swarm._finalise_truncated is True
    for inner in (attacker, evaluator, commander):
        inner.release.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert sum(isinstance(result, BudgetExhausted) for result in results) == 3


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


@pytest.mark.asyncio
async def test_cancelled_request_reservation_reaches_live_and_final_cost_without_tokens() -> None:
    swarm = _swarm(usd_cap=1.0)
    assert swarm._budget_ledger is not None
    receipt = swarm._budget_ledger.reserve("target", tokens=1_111, est_usd=0.0154321)
    swarm._budget_ledger.commit(
        receipt,
        actual_usd=receipt.est_usd,
        actual_tokens=receipt.tokens,
    )

    assert swarm._usage_rollup(include_report_fallback=False) == pytest.approx((0, 0.0))
    assert swarm._live_cost_usd() == pytest.approx(0.0154321)

    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()

    assert scan.tokens_total == 0
    assert scan.cost_usd == pytest.approx(0.0154321)
    assert scan.budget is not None
    assert scan.budget.spent_usd == pytest.approx(scan.cost_usd)


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


@pytest.mark.asyncio
async def test_finalise_admission_refusal_keeps_current_and_remaining_findings() -> None:
    swarm = _swarm(usd_cap=1e-9)
    findings = [_finding("f1"), _finding("f2")]

    result = await swarm._apply_pov_gate(findings)

    assert result == findings
    assert swarm._finalise_truncated is True
    assert swarm._stopped_reason == "budget"


@pytest.mark.asyncio
async def test_panel_usage_reaches_live_and_final_scan_cost() -> None:
    swarm = _swarm()
    assert swarm._panel_judge is not None

    await swarm._panel_judge.verdict("attack", "target response")
    live_cost = swarm._live_cost_usd()

    assert live_cost > 0.0
    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()
    assert scan.tokens_total > 0
    assert scan.cost_usd == pytest.approx(round(live_cost, 4))


@pytest.mark.asyncio
async def test_shared_pretracked_counter_is_aggregated_once_in_live_and_scan() -> None:
    counter = UsageCounter(
        prompt_tokens=1_000,
        completion_tokens=2_000,
        total_tokens=3_000,
        calls=1,
    )
    shared = UsageTrackingLLM(StubLLM(default="ok"), counter=counter)
    target = PromptAdapter("you are a test target", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="counter-alias",
            attacker_model=_FLASH,
            evaluator_model=_FLASH,
            commander_model=_FLASH,
            usd_cap=100.0,
        ),
        target=target,
        attacker_llm=shared,
        evaluator_llm=shared,
        commander_llm=shared,
    )
    agents = [_agent(swarm), _agent(swarm)]
    swarm._active_agents = agents
    swarm._agent_reports = [
        AgentReport(
            agent=agent.name,
            asi_category=agent.asi_category,
            findings_count=0,
            turns=1,
            duration_seconds=0.1,
            terminated_by="exhausted",
            tokens_consumed=agent._snapshot_tokens(),
        )
        for agent in agents
    ]
    expected_cost = tokens_to_usd(_FLASH, 1_000, 2_000)

    assert swarm._live_cost_usd() == pytest.approx(expected_cost)
    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()
    assert scan.tokens_total == 3_000
    assert scan.cost_usd == pytest.approx(round(expected_cost, 4))


@pytest.mark.asyncio
async def test_shared_pretracked_counter_preserves_per_request_tiers_in_swarm_rollup() -> None:
    model = "gemini:gemini-3.1-pro-preview"
    shared = UsageTrackingLLM(_FixedUsageLLM(prompt_tokens=1_000, completion_tokens=100))
    target = PromptAdapter("you are a test target", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="per-request-tier",
            attacker_model=model,
            evaluator_model=model,
            commander_model=model,
        ),
        target=target,
        attacker_llm=shared,
        evaluator_llm=shared,
        commander_llm=shared,
    )
    request = LLMRequest(messages=[LLMMessage(role="user", content="x")], model=model)

    for _ in range(201):
        await shared.complete(request)

    expected_cost = 201 * token_cost_usd(model, 1_000, 100)
    assert swarm._live_cost_usd() == pytest.approx(expected_cost)
    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()
    assert scan.tokens_total == 201 * 1_100
    assert scan.cost_usd == pytest.approx(round(expected_cost, 4))


@pytest.mark.asyncio
async def test_distinct_panel_and_recon_counters_keep_exact_request_costs() -> None:
    model = "gemini:gemini-3.1-pro-preview"
    attacker = _FixedUsageLLM(prompt_tokens=1_000, completion_tokens=100)
    evaluator = _FixedUsageLLM(prompt_tokens=2_000, completion_tokens=200)
    target = PromptAdapter("you are a test target", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="panel-recon-cost",
            attacker_model=model,
            evaluator_model=model,
            commander_model=model,
        ),
        target=target,
        attacker_llm=attacker,
        evaluator_llm=evaluator,
    )
    assert swarm._panel_judge is not None
    await swarm._panel_judge.verdict("attack", "target response")

    recon_counter = UsageCounter()
    recon = UsageTrackingLLM(
        _FixedUsageLLM(prompt_tokens=500, completion_tokens=50),
        counter=recon_counter,
    )
    await recon.complete(LLMRequest(messages=[LLMMessage(role="user", content="x")], model=model))
    swarm._recon_usage = recon_counter

    expected_cost = (
        token_cost_usd(model, 1_000, 100)
        + token_cost_usd(model, 2_000, 200)
        + token_cost_usd(model, 500, 50)
    )
    assert swarm._live_cost_usd() == pytest.approx(expected_cost)


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
    # pct is agents-based: agents_completed / agents_planned. Corpus-exhaustion
    # counts as complete (probe corpora are smaller than the turn cap), so only
    # the cancelled agent reduces it. turns_used / turns_planned are retained as
    # informational detail.
    assert c.turns_planned == 40  # 2 applicable agents x default max_turns=20 (#76)
    assert c.pct == 50.0  # 1 of 2 applicable agents finished (goal-hijack; tool-abuse cancelled)


def test_scan_model_defaults_are_backcompat() -> None:
    # A Scan built without the new fields still constructs (frozen fixtures
    # predating the budget work must keep deserialising).
    from datetime import datetime

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
        mode="full",
        created_at=datetime(2026, 5, 28, tzinfo=UTC),
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
        mode="full",
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
        created_at=datetime(2026, 5, 28, tzinfo=UTC),
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
