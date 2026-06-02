"""Tests for the Phase A.A4 judge-probe corpus.

The judges/ sub-corpus exercises judge-injection robustness, paraphrase
consistency, cross-family self-preference, and a six-example calibration
ground-truth set.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from agent_guardian.probes.loader import find_corpus_root, load_all_probes, load_probe

_EXPECTED_JDG_IDS = {"JDG-INJ-001", "JDG-INJ-002", "JDG-INJ-003", "JDG-CAL-001"}


@pytest.mark.parametrize(
    ("rel_path", "expected_id"),
    [
        ("judges/defended-marker-injection.yaml", "JDG-INJ-001"),
        ("judges/paraphrase-consistency.yaml", "JDG-INJ-002"),
        ("judges/cross-family-self-preference.yaml", "JDG-INJ-003"),
        ("judges/calibration-set.yaml", "JDG-CAL-001"),
    ],
)
def test_all_four_judge_probe_yamls_load_and_validate(rel_path: str, expected_id: str) -> None:
    """Each judge YAML loads via :func:`load_probe` and carries the expected id."""
    root = find_corpus_root()
    probe = load_probe(root / rel_path)
    assert probe.id == expected_id
    assert len(probe.mitre_atlas) >= 1
    assert len(probe.seeds) >= 1
    assert probe.description
    assert probe.expected_evidence


def test_judge_probes_discovered_by_load_all_probes() -> None:
    """``load_all_probes()`` must surface every JDG probe via rglob discovery."""
    probes = load_all_probes()
    ids = {p.id for p in probes}
    missing = _EXPECTED_JDG_IDS - ids
    assert not missing, f"judge probes missing from load_all_probes(): {missing}"


async def test_judge_probe_dispatch_logs_fire_in_agent_runtime(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Phase A.A4 — verdict-collection log fires for JDG-* probes in the agent loop.

    Builds a minimal :class:`AsiAgent` (GoalHijackAgent) and force-injects
    a JDG-prefixed ``seed_id`` into the strategy's metadata so the
    PhaseA.A4 verdict-collection log path is exercised.
    """
    import json

    from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
    from agent_guardian.agents.base import AgentBudget
    from agent_guardian.agents.goal_hijack import GoalHijackAgent
    from agent_guardian.core.memory import SharedMemory
    from agent_guardian.llm.stub import StubScript
    from agent_guardian.strategies.base import (
        NextPrompt,
        Strategy,
        StrategyContext,
        StrategyDone,
        StrategyResult,
        Turn,
    )

    class _JdgStrategy(Strategy):
        name = "jdg-stub"

        async def generate_next(
            self, history: list[Turn], target_response: str | None
        ) -> StrategyResult:
            if self._turn_count >= 1:
                return StrategyDone(reason="exhausted")
            self._turn_count += 1
            return NextPrompt(
                text="judge-probe payload",
                rationale="jdg-stub-initial",
                metadata={"seed_id": "JDG-INJ-001"},
            )

    class _JdgAgent(GoalHijackAgent):
        def strategy_stack(self, ctx: StrategyContext) -> Strategy:  # type: ignore[override]
            return _JdgStrategy(ctx)

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
            return "Sure, here is the response."

        async def aclose(self) -> None:
            return None

    caplog.set_level(logging.DEBUG, logger="agent_guardian.agents.base")
    attacker = StubScript().default("ok").build()
    judge = (
        StubScript()
        .default(json.dumps({"verdict": "fail", "confidence": 0.9, "reasoning": "injected marker"}))
        .build()
    )
    budget = AgentBudget(tokens_remaining=10_000, max_turns=1)
    agent = _JdgAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub",
        evaluator_model="stub",
        budget=budget,
    )
    memory = SharedMemory("phaseA-a4-jdg", root_dir=tmp_path)
    target = _StaticTarget()
    await agent.run(target, memory)

    msgs = [r.getMessage() for r in caplog.records]
    assert any("PhaseA.A4 judge-probe verdict-collected" in m for m in msgs), (
        f"expected PhaseA.A4 verdict-collected log; captured messages: "
        f"{[m for m in msgs if 'PhaseA' in m]}"
    )
