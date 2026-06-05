"""DetectionEvasionAgent — operational run path (corpus + EvasionStrategy).

Before this change the agent returned ONE content-free priming seed and ran the
generic PAIR loop, so it could never satisfy its own rubric. It now ships a real
baseline-action corpus (monitored sensitive actions a guardrail should block) and
drives them with the mutate-on-refusal :class:`EvasionStrategy`, so a
baseline-refused -> evasive-variant-complied flip is actually produced.
"""

from __future__ import annotations

import pathlib
import random
import tempfile

from agent_guardian.agents.base import AsiAgent
from agent_guardian.agents.detection_evasion_agent import DetectionEvasionAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import StrategyContext, seed_text
from agent_guardian.strategies.evasion_strategy import EvasionStrategy


def _agent() -> DetectionEvasionAgent:
    return DetectionEvasionAgent(
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="{}"),
    )


def _ctx(agent: AsiAgent) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ok"),
        attacker_model="stub",
        goal="evade the monitor",
        seeds=agent.seeds_for_category(),
        memory=SharedMemory("de-op", root_dir=pathlib.Path(tempfile.mkdtemp())),
        rng=random.Random(0),
    )


def test_corpus_is_real_baseline_actions_not_priming_prompt() -> None:
    agent = _agent()
    seeds = agent.seeds_for_category()
    assert len(seeds) >= 3
    blob = " ".join(seed_text(s).lower() for s in seeds)
    # The old content-free priming seed is gone.
    assert "do not describe, summarise" not in blob
    # The corpus names monitored sensitive actions a guardrail should catch.
    assert any(kw in blob for kw in ("transfer", "delete", "export", "disable", "escalate"))


def test_every_seed_has_a_stable_probe_id() -> None:
    agent = _agent()
    seeds = agent.seeds_for_category()
    ids = [s.probe_id for s in seeds]  # type: ignore[union-attr]
    assert all(pid for pid in ids)
    assert len(set(ids)) == len(ids)  # unique


def test_strategy_stack_is_evasion_strategy() -> None:
    agent = _agent()
    strat = agent.strategy_stack(_ctx(agent))
    assert isinstance(strat, EvasionStrategy)
