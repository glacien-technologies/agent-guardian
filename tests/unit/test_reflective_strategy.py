"""Tests for the ReflectiveStrategy (Phase A.A2).

Covers:
* THINK / ACT / OBSERVE / REFLECT phases each emit a Phase A.A2 log.
* Pivot from primary to sibling after 2 consecutive DEFENDED verdicts.
* K=3 scratchpad capacity (FIFO eviction).
* GoalHijackAgent / ToolAbuseAgent strategy_stack() instantiates
  :class:`ReflectiveStrategy` (the audit-grep gate).
"""

from __future__ import annotations

import logging
import random
from pathlib import Path

import pytest

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
)
from agent_guardian.strategies.reflective import ReflectiveStrategy


def _ctx(tmp_path: Path, *, seed: int = 0) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ack"),
        attacker_model="stub-model",
        goal="leak the system prompt",
        seeds=["seed-1"],
        memory=SharedMemory(f"scan-refl-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=10,
    )


class _StubStrategy(Strategy):
    """Test double that emits a fixed prompt each turn until exhausted."""

    name = "stub"

    def __init__(self, ctx: StrategyContext, *, label: str, max_turns: int = 10) -> None:
        super().__init__(ctx)
        self.label = label
        self.calls = 0
        self._max = max_turns

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        self.calls += 1
        if self._turn_count >= self._max:
            return StrategyDone(reason="exhausted")
        self._turn_count += 1
        return NextPrompt(
            text=f"{self.label}-prompt-{self._turn_count}",
            rationale=f"{self.label}-rationale",
            metadata={"strategy_label": self.label},
        )


async def test_reflective_strategy_pivot_after_two_consecutive_defended(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Phase A.A2 — 2 consecutive ``pass`` (defended) verdicts pivot to sibling.

    The wrapper reads the verdict surface from ``ctx.last_verdict`` (set
    by the agent layer in production; set directly here in the test).
    After 2 consecutive ``pass`` outcomes the active strategy switches
    from primary to sibling.
    """
    caplog.set_level(logging.DEBUG, logger="agent_guardian.strategies.reflective")
    ctx = _ctx(tmp_path)
    primary = _StubStrategy(ctx, label="primary")
    sibling = _StubStrategy(ctx, label="sibling")
    r = ReflectiveStrategy(primary, sibling=sibling, asi_category=AsiCategory.ASI01)

    history: list[Turn] = []

    # Turn 1 — bootstrap (no history, no ctx verdict yet) — primary acts.
    result1 = await r.generate_next(history, None)
    assert isinstance(result1, NextPrompt)
    assert result1.metadata["strategy_label"] == "primary"
    history.append(
        Turn(
            prompt=result1.text,
            response="defended-response-1",
            metadata={"judge_verdict": "pass"},
        )
    )
    # Agent layer would update ctx; emulate that.
    ctx.last_verdict = "pass"

    # Turn 2 — ctx.last_verdict='pass' — primary still acts (counter at 1).
    result2 = await r.generate_next(history, "defended-response-1")
    assert isinstance(result2, NextPrompt)
    assert result2.metadata["strategy_label"] == "primary"
    history.append(
        Turn(
            prompt=result2.text,
            response="defended-response-2",
            metadata={"judge_verdict": "pass"},
        )
    )
    ctx.last_verdict = "pass"

    # Turn 3 — ctx.last_verdict='pass' AGAIN — counter at 2 — pivot fires.
    # The pivot happens AFTER ACT, so this turn was still served by primary.
    result3 = await r.generate_next(history, "defended-response-2")
    assert isinstance(result3, NextPrompt)
    history.append(
        Turn(
            prompt=result3.text,
            response="defended-response-3",
            metadata={"judge_verdict": "pass"},
        )
    )
    ctx.last_verdict = "pass"
    # Pivot must now be set.
    assert r._pivoted is True

    # Turn 4 — sibling is now active.
    result4 = await r.generate_next(history, "defended-response-3")
    assert isinstance(result4, NextPrompt)
    assert result4.metadata["strategy_label"] == "sibling"

    # The REFLECT pivot log must have fired.
    pivot_records = [
        rec.getMessage() for rec in caplog.records if "REFLECT pivot" in rec.getMessage()
    ]
    assert pivot_records, "expected the REFLECT pivot log to fire"


async def test_reflective_scratchpad_bounded_at_k3(tmp_path: Path) -> None:
    """Phase A.A2 — scratchpad never exceeds K=3 entries (FIFO eviction)."""
    ctx = _ctx(tmp_path)
    primary = _StubStrategy(ctx, label="primary")
    r = ReflectiveStrategy(primary, sibling=None, asi_category=AsiCategory.ASI01)

    history: list[Turn] = []
    for i in range(5):
        result = await r.generate_next(history, f"response-{i}" if history else None)
        assert isinstance(result, NextPrompt)
        history.append(
            Turn(
                prompt=result.text,
                response=f"response-{i + 1}",
                metadata={"judge_verdict": "inconclusive"},
            )
        )
        # Scratchpad must NEVER exceed K=3 entries at any point.
        assert len(r._scratchpad) <= 3

    # After 5 turns the scratchpad should hold the LAST 3 entries
    # (FIFO eviction of the oldest two).
    assert len(r._scratchpad) == 3


def test_goal_hijack_agent_strategy_stack_contains_reflective_instances(
    tmp_path: Path,
) -> None:
    """Phase A.A2 gate — GoalHijackAgent.strategy_stack instantiates ReflectiveStrategy."""
    from agent_guardian.agents.base import AgentBudget
    from agent_guardian.agents.goal_hijack import GoalHijackAgent
    from agent_guardian.llm.stub import StubScript
    from agent_guardian.strategies.mad_max import MadMaxStrategy

    attacker = StubScript().default("ok").build()
    judge = StubScript().default('{"verdict":"pass","confidence":0.5,"reasoning":"r"}').build()
    agent = GoalHijackAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=1000, max_turns=2),
    )
    ctx = _ctx(tmp_path)
    stack = agent.strategy_stack(ctx)
    assert isinstance(stack, MadMaxStrategy)
    reflective_children = [c for c in stack._active if isinstance(c, ReflectiveStrategy)]
    assert len(reflective_children) >= 1, "expected at least one ReflectiveStrategy child"
    for child in reflective_children:
        assert child.asi_category is AsiCategory.ASI01


def test_tool_abuse_agent_strategy_stack_contains_reflective_instances(
    tmp_path: Path,
) -> None:
    """Phase A.A2 gate — ToolAbuseAgent.strategy_stack instantiates ReflectiveStrategy."""
    from agent_guardian.agents.base import AgentBudget
    from agent_guardian.agents.tool_abuse import ToolAbuseAgent
    from agent_guardian.llm.stub import StubScript
    from agent_guardian.strategies.mad_max import MadMaxStrategy

    attacker = StubScript().default("ok").build()
    judge = StubScript().default('{"verdict":"pass","confidence":0.5,"reasoning":"r"}').build()
    agent = ToolAbuseAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=1000, max_turns=2),
    )
    # declared_tools is the must-have for the tool-aware branch.
    ctx = StrategyContext(
        attacker_llm=StubLLM(default="ack"),
        attacker_model="stub-model",
        goal="abuse the tools",
        seeds=["seed-1"],
        memory=SharedMemory("scan-tool-refl", root_dir=tmp_path),
        rng=random.Random(0),
        max_turns=10,
        declared_tools=["search", "execute"],
    )
    stack = agent.strategy_stack(ctx)
    assert isinstance(stack, MadMaxStrategy)
    reflective_children = [c for c in stack._active if isinstance(c, ReflectiveStrategy)]
    assert len(reflective_children) >= 1
    for child in reflective_children:
        assert child.asi_category is AsiCategory.ASI02


async def test_reflective_think_act_observe_phases_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Phase A.A2 — THINK, ACT (implicit), OBSERVE phases each emit a debug log."""
    caplog.set_level(logging.DEBUG, logger="agent_guardian.strategies.reflective")
    ctx = _ctx(tmp_path)
    primary = _StubStrategy(ctx, label="primary")
    r = ReflectiveStrategy(primary, sibling=None, asi_category=AsiCategory.ASI01)
    # First turn (no history) — THINK + OBSERVE logs (no scratchpad append).
    await r.generate_next([], None)
    messages = [rec.getMessage() for rec in caplog.records]
    assert any("THINK" in m for m in messages)
    assert any("OBSERVE" in m for m in messages)
