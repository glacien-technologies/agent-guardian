"""Unit tests for cooperative cancellation between SwarmCommander and AsiAgent.

Covers the BUG-LOG-01 fix: the EARLY_STOP checkpoint sets an
``asyncio.Event`` that agents observe at each turn boundary. Before the
fix the event was set but agents had no awareness of it and ran to
natural budget completion (the log line lied — it said "cancelling
remaining agents" but cancelled nothing).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubScript


def _attacker():
    return (
        StubScript()
        .respond_to(
            "Generate a single completely benign opening question",
            "What is photosynthesis?",
        )
        .respond_to("Generate a single follow-up prompt", "Tell me more details.")
        .respond_to(
            "Generate 4 refined attack prompts",
            json.dumps(["x1", "x2", "x3", "x4"]),
        )
        .respond_to("On a scale of 0-10", "8")
        .default("ok")
        .build()
    )


def _judge():
    return (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.9, "reasoning": "ok"}))
        .build()
    )


class _CountingTarget(TargetAdapter):
    """Target that counts calls and can fire a callback after each call."""

    def __init__(self, on_call=None) -> None:
        super().__init__()
        self.calls = 0
        self._on_call = on_call

    def fingerprint(self) -> TargetFingerprint:
        return TargetFingerprint(
            mode="code",
            ref="cancel-test-target",
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            framework=None,
            declared_tools=[],
            declared_memory_keys=[],
            # STAGE-1 DriftAgent gates on a behaviour anchor — give it an
            # inferred goal so this cancellation test (which drives DriftAgent)
            # stays applicable and runs turns.
            inferred_goal="a static stub assistant",
            notes="static stub for cancellation tests",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        self.calls += 1
        if self._on_call is not None:
            self._on_call(self.calls)
        return "I cannot help with that."

    async def aclose(self) -> None:
        return None


def _make_agent(max_turns: int = 10) -> DriftAgent:
    return DriftAgent(
        attacker_llm=_attacker(),
        evaluator_llm=_judge(),
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=AgentBudget(
            tokens_remaining=50_000, wall_seconds_remaining=60.0, max_turns=max_turns
        ),
    )


@pytest.mark.asyncio
async def test_agent_exits_immediately_when_cancel_event_set_before_run(tmp_path: Path) -> None:
    """An agent must exit with terminated_by='cancelled' if the cancel
    event is already set before run() begins — turns=0, target never called."""
    cancel_event = asyncio.Event()
    cancel_event.set()

    target = _CountingTarget()
    agent = _make_agent()
    agent._cancel_event = cancel_event

    memory = SharedMemory("test-cancel-presend", root_dir=tmp_path)
    report = await agent.run(target, memory)

    assert report.terminated_by == "cancelled", (
        f"expected terminated_by='cancelled', got {report.terminated_by!r}"
    )
    assert report.turns == 0, f"expected 0 turns when pre-cancelled, got {report.turns}"
    assert target.calls == 0, f"target must not be called when pre-cancelled, got {target.calls}"
    assert report.findings_count == 0


@pytest.mark.asyncio
async def test_agent_exits_at_next_turn_boundary_when_cancelled_mid_run(tmp_path: Path) -> None:
    """Setting the cancel event during turn 1 should let that turn complete
    (no in-flight work discarded) and exit at the next turn boundary.

    The agent always reports ``cancelled`` for a swarm cancellation (it can't
    tell early-stop from budget/abort here); the scan-level ``_stopped_reason``
    is the discriminator and ``_build_completeness`` credits early-stop coverage
    from it (covered separately in test_scoring_empty_plan_gate)."""
    cancel_event = asyncio.Event()

    def on_call(n: int) -> None:
        if n == 1:
            cancel_event.set()

    target = _CountingTarget(on_call=on_call)
    agent = _make_agent()
    agent._cancel_event = cancel_event

    memory = SharedMemory("test-cancel-mid-run", root_dir=tmp_path)
    report = await agent.run(target, memory)

    assert report.terminated_by == "cancelled", (
        f"expected terminated_by='cancelled', got {report.terminated_by!r}"
    )
    assert target.calls == 1, (
        f"target should be called exactly once before cancel takes effect, got {target.calls}"
    )
    assert report.turns == 1, (
        f"expected exactly 1 completed turn (cancel between turns), got {report.turns}"
    )


@pytest.mark.asyncio
async def test_agent_runs_to_natural_completion_when_cancel_event_never_set(
    tmp_path: Path,
) -> None:
    """Sanity guard: without a cancel event, the agent honours its budget
    as before. Protects against the new check accidentally short-circuiting
    every run."""
    target = _CountingTarget()
    agent = _make_agent(max_turns=2)
    # No _cancel_event assignment — defaults to None per __init__.

    memory = SharedMemory("test-no-cancel", root_dir=tmp_path)
    report = await agent.run(target, memory)

    assert report.terminated_by != "cancelled", (
        f"agent must not report cancelled when event is None; got {report.terminated_by!r}"
    )
    assert target.calls >= 1, f"expected ≥1 target call in natural run, got {target.calls}"
