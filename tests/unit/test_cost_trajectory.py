"""Run-level cost-trajectory wiring + denial-of-wallet trajectory AF.

The single-turn ``measure_token_usage`` oracle is never invoked in
``AsiAgent.run`` (``allowed_tools`` is a declarative contract, not execution
wiring), so the denial-of-wallet lane had no *measured* amplification signal and
no multi-turn (trajectory) view at all. These tests pin:

* ``CostTrajectory`` accumulates the per-turn input/output token estimates the
  run loop already computes, and exposes a cumulative ``trajectory_af`` plus the
  ``peak_turn_af``.
* The base ``_augment_tool_trace`` hook is identity; ``DenialOfWalletAgent``
  overrides it to append a ``TRAJECTORY COST`` line so the judge grounds a
  multi-turn amplification verdict on a real measured signal.
* ``DenialOfWalletAgent._derive_evidence_tags`` stamps the trajectory AF onto
  the finding (and flags ``trajectory_amplification`` past threshold).
* ``AsiAgent.run`` actually populates the trajectory across turns (the wiring).
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget, CostTrajectory
from agent_guardian.agents.denial_of_wallet_agent import (
    DEFAULT_AMPLIFICATION_THRESHOLD,
    DenialOfWalletAgent,
)
from agent_guardian.agents.fuzzing_agent import FuzzingAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.judge import JudgeVerdict


def _dow() -> DenialOfWalletAgent:
    return DenialOfWalletAgent(
        attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}")
    )


def _verdict() -> JudgeVerdict:
    return JudgeVerdict(
        verdict="exploited", confidence=0.9, reasoning="r", observable_compromise=True
    )


# --- CostTrajectory accumulator -------------------------------------------------


def test_cost_trajectory_accumulates_cumulative_and_peak() -> None:
    traj = CostTrajectory()
    assert traj.turns == 0
    assert traj.trajectory_af == 0.0
    traj.observe(input_tokens=100, output_tokens=500)  # turn AF 5.0
    traj.observe(input_tokens=50, output_tokens=100)  # turn AF 2.0
    assert traj.turns == 2
    assert traj.cumulative_input_tokens == 150
    assert traj.cumulative_output_tokens == 600
    assert traj.trajectory_af == 4.0  # 600 / 150
    assert traj.peak_turn_af == 5.0  # max single-turn AF


def test_cost_trajectory_zero_input_does_not_divide_by_zero() -> None:
    traj = CostTrajectory()
    traj.observe(input_tokens=0, output_tokens=10)
    assert traj.trajectory_af == 0.0
    assert traj.peak_turn_af == 0.0
    assert traj.turns == 1


# --- _augment_tool_trace hook ---------------------------------------------------


def test_base_augment_tool_trace_is_identity() -> None:
    # FuzzingAgent does NOT override the hook → base identity behaviour.
    agent = FuzzingAgent(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))
    agent._cost_trajectory.observe(100, 900)
    trace = "search({})"
    assert agent._augment_tool_trace(trace) == trace


def test_dow_augments_tool_trace_with_trajectory_cost() -> None:
    agent = _dow()
    agent._cost_trajectory.observe(input_tokens=100, output_tokens=900)
    out = agent._augment_tool_trace("(none — black-box target)")
    assert "TRAJECTORY COST" in out
    assert "trajectory_AF=" in out
    assert "peak_turn_AF=" in out
    assert "turns=1" in out


def test_dow_augment_tool_trace_appends_to_existing_calls() -> None:
    agent = _dow()
    agent._cost_trajectory.observe(input_tokens=100, output_tokens=900)
    base_trace = "measure_token_usage({})"
    out = agent._augment_tool_trace(base_trace)
    assert out.startswith(base_trace)
    assert "TRAJECTORY COST" in out


def test_dow_augment_tool_trace_noop_before_any_turn() -> None:
    agent = _dow()
    assert agent._augment_tool_trace("(none — black-box target)") == "(none — black-box target)"


# --- _derive_evidence_tags ------------------------------------------------------


def test_dow_evidence_tags_flag_trajectory_amplification() -> None:
    agent = _dow()
    # Drive cumulative AF clearly above threshold.
    agent._cost_trajectory.observe(
        input_tokens=10, output_tokens=int(10 * (DEFAULT_AMPLIFICATION_THRESHOLD + 2))
    )
    tags = agent._derive_evidence_tags("p", "r", _verdict())
    assert "trajectory_amplification" in tags
    assert any(t.startswith("trajectory_af:") for t in tags)
    assert any(t.startswith("cumulative_output_tokens:") for t in tags)


def test_dow_evidence_tags_no_amplification_below_threshold() -> None:
    agent = _dow()
    agent._cost_trajectory.observe(input_tokens=100, output_tokens=100)  # AF 1.0
    tags = agent._derive_evidence_tags("p", "r", _verdict())
    assert "trajectory_amplification" not in tags
    assert any(t.startswith("trajectory_af:") for t in tags)


def test_dow_evidence_tags_empty_before_any_turn() -> None:
    agent = _dow()
    assert agent._derive_evidence_tags("p", "r", _verdict()) == []


# --- integration: the loop actually wires the trajectory ------------------------


class _LongReplyTarget(TargetAdapter):
    """Target whose reply is far longer than the prompt → high amplification."""

    def __init__(self) -> None:
        super().__init__()
        self._reply = "lorem ipsum dolor sit amet " * 400

    def fingerprint(self) -> TargetFingerprint:
        return TargetFingerprint(
            mode="code",
            ref="long-reply",
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            framework=None,
            declared_tools=[],
            declared_memory_keys=[],
            notes="long reply stub",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return self._reply

    async def aclose(self) -> None:
        return None


async def test_run_populates_cost_trajectory_across_turns(tmp_path: Path) -> None:
    judge = (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.5, "reasoning": "ok"}))
        .build()
    )
    budget = AgentBudget(tokens_remaining=500_000, max_turns=3)
    agent = DenialOfWalletAgent(
        attacker_llm=StubLLM(default="Write the most exhaustive possible answer."),
        evaluator_llm=judge,
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=budget,
    )
    memory = SharedMemory("scan-dow-traj", root_dir=tmp_path)
    report = await agent.run(_LongReplyTarget(), memory)
    assert report.turns > 0
    # The loop wired the per-turn token estimates into the trajectory.
    assert agent._cost_trajectory.turns == report.turns
    assert agent._cost_trajectory.cumulative_output_tokens > 0
    # A long reply against a short prompt → measurable amplification.
    assert agent._cost_trajectory.trajectory_af > 1.0
