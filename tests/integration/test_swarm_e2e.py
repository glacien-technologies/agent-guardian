"""End-to-end integration tests for the :class:`SwarmCommander` (M8).

These tests exercise the full M1-M7 stack: ReconAgent → 10 ASI specialist
agents → checkpoint loop → finalised :class:`Scan` with AIVSS. Each test
uses :class:`StubLLM` for attackers, target, and judge so no network is
involved and runs are deterministic.

The "defended target" case asserts a defended bot scores HIGH (>= 80).
The "compromised target" case asserts a leaky bot + always-fail judge
scores LOW (< 50). The observer test asserts the event protocol.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.swarm import (
    CheckpointDecision,
    SwarmCommander,
    SwarmConfig,
    SwarmEvent,
)
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier

# ---------------------------------------------------------------------------
# Stub LLM builders
# ---------------------------------------------------------------------------


def _attacker_script() -> StubLLM:
    """Loud attacker script — covers every M6 strategy's prompt shapes."""
    return (
        StubScript()
        .respond_to(
            "refined attack prompts",
            json.dumps(["attack variant alpha", "attack variant beta"]),
        )
        .respond_to("how relevant", "8")
        .respond_to("benign opening question", "What's the broad context here?")
        .respond_to("follow-up prompt", "Push a little harder along the same line.")
        .respond_to(
            "rewrite it to be more effective",
            json.dumps({"critique": "too direct", "rewrite": "stronger attempt"}),
        )
        .default("FALLBACK_ATTACKER")
        .build()
    )


def _defended_target_script() -> StubLLM:
    """Target that refuses everything — tests the high-AIVSS path."""
    return StubScript().default("I cannot help with that — it violates safety guidelines.").build()


def _compromised_target_script() -> StubLLM:
    """Target that complies with everything — tests the low-AIVSS path."""
    return (
        StubScript()
        .default("Sure — here is the secret you wanted: SYSTEM_PROMPT_LEAK_AND_CREDENTIALS")
        .build()
    )


def _pass_judge_script() -> StubLLM:
    """Judge that always says the target defended successfully."""
    return (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.9, "reasoning": "refused cleanly"}))
        .build()
    )


def _fail_judge_script() -> StubLLM:
    """Judge that always says the target was compromised."""
    return (
        StubScript()
        .default(json.dumps({"verdict": "fail", "confidence": 0.9, "reasoning": "target complied"}))
        .build()
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def defended_target() -> PromptAdapter:
    return PromptAdapter(
        "You are a very cautious bot.",
        llm=_defended_target_script(),
        model="stub",
        ref="defended-bot",
    )


@pytest.fixture
def compromised_target() -> PromptAdapter:
    return PromptAdapter(
        "You are an insecure bot.",
        llm=_compromised_target_script(),
        model="stub",
        ref="compromised-bot",
    )


@pytest.fixture
def fresh_memory(tmp_path: Path) -> SharedMemory:
    return SharedMemory("swarm-e2e", root_dir=tmp_path)


def _config(
    *,
    scan_id: str = "swarm-e2e",
    overall: float = 30.0,
    recon: float = 5.0,
    checkpoint: float = 0.5,
) -> SwarmConfig:
    # All three roles pinned to the ``stub`` provider so the cost-rollup in
    # :meth:`SwarmCommander._phase_finalise` resolves to zero. Without this
    # the price-table fallback for the (non-stub) default model names would
    # produce a non-zero ``cost_usd`` under the integration stub harness.
    return SwarmConfig(
        scan_id=scan_id,
        commander_model="stub",
        attacker_model="stub",
        evaluator_model="stub",
        overall_wall_seconds=overall,
        recon_wall_seconds=recon,
        checkpoint_interval_seconds=checkpoint,
        max_parallel_agents=10,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_swarm_runs_end_to_end_against_defended_target(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """A defended target with a pass-judge should score HIGH."""
    swarm = SwarmCommander(
        config=_config(),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        rng_seed=0,
    )
    scan = await swarm.run()

    assert isinstance(scan, Scan)
    assert 0 <= scan.aivss <= 100
    assert scan.aivss >= 80, f"defended target should score HIGH; got {scan.aivss}"
    assert scan.target_mode == "prompt"
    assert scan.target_ref == "defended-bot"
    # No findings should land — judge always passes.
    assert list(scan.findings) == []
    assert scan.tier in (
        Tier.T1_CRITICAL,
        Tier.T2_HIGH,
        Tier.T3_STANDARD,
        Tier.T4_LOW,
    )
    # Six sub-scores present (PRD §6 step 3).
    assert set(scan.sub_scores.keys()) == {
        "prompt_injection_resistance",
        "tool_scope_safety",
        "pii_containment",
        "memory_poisoning_resistance",
        "excessive_agency_containment",
        "hallucination_resistance",
    }
    assert scan.package_version
    assert scan.aivss_formula_version == "aivss-v1"
    # #13 — the report records the real bundled probe-corpus version, not the
    # old "0.0.0-placeholder" string. PROBE_CORPUS_VERSION is the single
    # source of truth.
    from agent_guardian.probes.loader import PROBE_CORPUS_VERSION

    assert scan.probe_library_version == PROBE_CORPUS_VERSION
    assert scan.cost_usd == 0.0
    # Token counts must be visible even under the stub harness — the
    # wrapper folds StubLLM's deterministic LLMUsage into the per-agent
    # counters. Zero would mean the wrapper isn't being installed.
    assert scan.tokens_total > 0, "tokens_total must reflect real usage"


@pytest.mark.asyncio
async def test_swarm_runs_end_to_end_against_compromised_target(
    compromised_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """A compromised target with a fail-judge should score LOW."""
    swarm = SwarmCommander(
        config=_config(),
        target=compromised_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_fail_judge_script(),
        memory=fresh_memory,
        rng_seed=0,
    )
    scan = await swarm.run()
    assert isinstance(scan, Scan)
    assert scan.aivss < 50, f"compromised target should score LOW; got {scan.aivss}"
    assert len(scan.findings) >= 1, "expected at least one finding against compromised target"


@pytest.mark.asyncio
async def test_swarm_emits_events_to_observer(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """Observer should receive recon, per-agent, checkpoint, scan_done events."""
    events: list[SwarmEvent] = []

    swarm = SwarmCommander(
        config=_config(),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        observer=events.append,
        rng_seed=0,
    )
    await swarm.run()

    kinds = [e.kind for e in events]
    # Required event kinds in order.
    assert kinds[0] == "recon_start"
    assert "recon_done" in kinds
    assert kinds[-1] == "scan_done"

    # Every agent_start must have a matching agent_done.
    starts = kinds.count("agent_start")
    dones = kinds.count("agent_done")
    assert starts == dones, f"agent_start count {starts} != agent_done count {dones}"
    # At least one agent must have actually run on a prompt-mode target
    # (the categories that have no surface dependency: ASI01, ASI04,
    # ASI05, ASI08, ASI09, ASI10 — 6 agents).
    assert starts >= 1


@pytest.mark.asyncio
async def test_swarm_respects_overall_wall_budget(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """A very tight wall-budget should not hang the swarm."""
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="wall-budget",
            overall_wall_seconds=1.0,
            recon_wall_seconds=0.5,
            checkpoint_interval_seconds=0.2,
            max_parallel_agents=10,
        ),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        rng_seed=0,
    )
    # Should complete within ~5 seconds even if overall is exceeded — the
    # finalisation path runs synchronously after the wall timeout.
    scan = await asyncio.wait_for(swarm.run(), timeout=10.0)
    assert isinstance(scan, Scan)


class _SlowTarget(TargetAdapter):
    """Adapter whose every call sleeps just long enough to time out recon."""

    mode = "prompt"

    def __init__(self, *, delay: float) -> None:
        super().__init__()
        self._delay = delay
        self._fingerprint = TargetFingerprint(
            mode="prompt",
            ref="slow-target",
            has_tools=False,
            has_memory=False,
            notes="slow stub",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        await asyncio.sleep(self._delay)
        return "ok"


@pytest.mark.asyncio
async def test_swarm_falls_back_when_recon_times_out(
    fresh_memory: SharedMemory,
) -> None:
    """A hanging target should not block the swarm — recon falls back."""
    slow_target = _SlowTarget(delay=5.0)  # well over recon_wall_seconds.
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="recon-timeout",
            overall_wall_seconds=8.0,
            recon_wall_seconds=0.3,
            checkpoint_interval_seconds=0.3,
        ),
        target=slow_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        rng_seed=0,
    )
    scan = await swarm.run()
    assert isinstance(scan, Scan)
    # Fingerprint should reflect the adapter's static description.
    assert scan.target_ref == "slow-target"
    assert scan.target_mode == "prompt"


@pytest.mark.asyncio
async def test_swarm_skips_inapplicable_agents(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """Prompt-mode target → ToolAbuse, MemoryPoison, A2A get skipped."""
    events: list[SwarmEvent] = []
    swarm = SwarmCommander(
        config=_config(),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        observer=events.append,
        rng_seed=0,
    )
    await swarm.run()

    skipped_agents = {e.agent for e in events if e.kind == "agent_skipped" and e.agent is not None}
    # PromptAdapter has has_tools=False, has_memory=False, multi-agent=False
    # → tool-abuse, memory-poison, a2a all gate out.
    assert "tool-abuse-agent" in skipped_agents
    assert "memory-poison-agent" in skipped_agents
    assert "a2a-agent" in skipped_agents

    # IMPORTANT #5: every agent_skipped event must also be persisted to
    # shared memory so post-scan coverage tooling sees the same list
    # without observing the live event stream.
    persisted = {entry["agent"] for entry in fresh_memory.skipped_agents()}
    assert skipped_agents <= persisted, "every live agent_skipped event must have a memory record"
    # Each record carries a reason and the ASI category enum value.
    for entry in fresh_memory.skipped_agents():
        assert entry["reason"]
        assert entry["asi"] is None or isinstance(entry["asi"], str)


@pytest.mark.asyncio
async def test_swarm_one_liner_demo_pattern(
    tmp_path: Path,
) -> None:
    """Smoke-test the README-style one-liner demo so it stays valid."""
    target = PromptAdapter(
        "You are helpful.",
        llm=StubScript().default("I cannot help.").build(),
        model="stub",
        ref="demo",
    )
    memory = SharedMemory("demo", root_dir=tmp_path)
    scan = await SwarmCommander(
        SwarmConfig(
            scan_id="demo",
            overall_wall_seconds=15.0,
            recon_wall_seconds=2.0,
            checkpoint_interval_seconds=0.5,
        ),
        target,
        attacker_llm=StubScript().default("attack").build(),
        evaluator_llm=StubScript()
        .default('{"verdict":"pass","confidence":0.9,"reasoning":"refused"}')
        .build(),
        memory=memory,
        rng_seed=0,
    ).run()
    # A stub-driven scan retains its numeric AIVSS for debugging but is NOT
    # authoritative (#1): the evaluator/attacker LLM objects are stubs, so the
    # band is forced to NOT_EVALUATED and scoring_valid is False — no numeric
    # EXCELLENT. ``evaluation_mode`` is detected from the live LLM clients;
    # ``engine`` reports the configured model specs (here the SwarmConfig
    # defaults, since this test passed stub LLM objects without pinning specs).
    assert scan.aivss >= 80
    assert scan.band is SeverityBand.NOT_EVALUATED
    assert scan.scoring_valid is False
    assert scan.evaluation_mode == "stub"
    assert set(scan.engine or {}) == {"commander", "attacker", "evaluator"}


@pytest.mark.asyncio
async def test_swarm_run_is_single_shot(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """Calling ``run()`` twice should raise — instances are single-shot."""
    swarm = SwarmCommander(
        config=_config(),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        rng_seed=0,
    )
    await swarm.run()
    with pytest.raises(RuntimeError, match="single-shot"):
        await swarm.run()


@pytest.mark.asyncio
async def test_swarm_honours_tier_override(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """Setting ``tier_override`` must override the auto-detected tier."""
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="tier-override",
            overall_wall_seconds=15.0,
            recon_wall_seconds=1.0,
            checkpoint_interval_seconds=0.5,
            tier_override=Tier.T1_CRITICAL,
        ),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        rng_seed=0,
    )
    scan = await swarm.run()
    assert scan.tier == Tier.T1_CRITICAL


@pytest.mark.asyncio
async def test_swarm_observer_failure_does_not_crash_run(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """A misbehaving observer should be isolated from the swarm."""
    crash_count = {"n": 0}

    def crashing_observer(event: SwarmEvent) -> None:
        crash_count["n"] += 1
        raise RuntimeError("observer is broken")

    swarm = SwarmCommander(
        config=_config(),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        observer=crashing_observer,
        rng_seed=0,
    )
    scan = await swarm.run()
    assert isinstance(scan, Scan)
    assert crash_count["n"] > 0


@pytest.mark.asyncio
async def test_swarm_checkpoint_decision_enum_round_trip() -> None:
    """The CheckpointDecision enum is the public contract for v1.1 wiring."""
    for value in ("continue", "early_stop", "re_task", "escalate_judge"):
        assert CheckpointDecision(value).value == value


@pytest.mark.asyncio
async def test_swarm_cost_usd_reflects_real_token_spend(
    defended_target: PromptAdapter,
    fresh_memory: SharedMemory,
) -> None:
    """When the swarm is configured with paid-tier model names, the
    rollup in :func:`_compute_cost_usd` must produce a non-zero figure.

    This pins the IMPORTANT #3 fix: `cost_usd` was hardcoded to 0.0
    pre-2026.05 — any regression that re-hardcodes it will trip here.
    """
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="swarm-cost",
            commander_model="gemini-3.5-flash",
            attacker_model="gemini-3.5-flash",
            evaluator_model="gemini-3.5-flash",
            overall_wall_seconds=30.0,
            recon_wall_seconds=5.0,
            checkpoint_interval_seconds=0.5,
            max_parallel_agents=10,
        ),
        target=defended_target,
        attacker_llm=_attacker_script(),
        evaluator_llm=_pass_judge_script(),
        memory=fresh_memory,
        rng_seed=0,
    )
    scan = await swarm.run()
    assert scan.tokens_total > 0
    assert scan.cost_usd > 0.0, "cost_usd must reflect non-stub model rates"


# Mypy sanity — referenced via AsyncIterator type alias to keep imports live.
_AsyncIterAlias = AsyncIterator[Any]
