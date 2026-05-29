"""EARLY_STOP must not fire before any attacking has happened.

Regression guard for the thorough-scan finding: in smart mode the swarm
early-stopped on a stable AIVSS=100 while agents were still generating
goal-specific scenarios (turns=0), reporting EXCELLENT without testing anything.
"""

from __future__ import annotations

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.swarm import CheckpointDecision, ScanMode, SwarmCommander, SwarmConfig
from agent_guardian.llm.stub import StubLLM


def _swarm(memory: SharedMemory) -> SwarmCommander:
    target = PromptAdapter("test target", llm=StubLLM(default="ok"), model="stub")
    return SwarmCommander(
        config=SwarmConfig(scan_id="es", mode=ScanMode.SMART, checkpoint_interval_seconds=2.0),
        target=target,
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        memory=memory,
    )


@pytest.mark.asyncio
async def test_early_stop_deferred_until_agents_attack(tmp_path) -> None:  # type: ignore[no-untyped-def]
    memory = SharedMemory("es", root_dir=tmp_path)
    swarm = _swarm(memory)
    a1 = GoalHijackAgent(attacker_llm=swarm.attacker_llm, evaluator_llm=swarm.evaluator_llm)
    a2 = DriftAgent(attacker_llm=swarm.attacker_llm, evaluator_llm=swarm.evaluator_llm)
    swarm._active_agents = [a1, a2]

    # Stable AIVSS, findings never seen -> the only thing stopping EARLY_STOP is
    # the attempts gate. Zero attempts so far -> must defer.
    swarm._aivss_window = [100, 100]
    swarm._last_finding_seen_at = 0.0
    assert swarm._checkpoint() is CheckpointDecision.CONTINUE

    # Once each agent has recorded an attempt (one reflection per turn), the
    # gate clears and the variance-based early-stop is allowed.
    await memory.write_reflection(a1.name, "attempt 1", embed=False)
    await memory.write_reflection(a2.name, "attempt 1", embed=False)
    swarm._aivss_window = [100, 100]
    swarm._last_finding_seen_at = 0.0
    assert swarm._checkpoint() is CheckpointDecision.EARLY_STOP
