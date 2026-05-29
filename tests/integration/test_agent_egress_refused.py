"""Integration: an egress-refused turn is recorded as not_tested (#4).

When the RoE egress gate raises :class:`~agent_guardian.core.roe.EgressRefused`
from the target ``call`` chokepoint, the agent turn loop must:

* NOT count the turn as a landed attack (no finding, no judged turn);
* NOT treat it as an error (it terminated cleanly);
* count it in ``AgentReport.not_tested_turns``;
* persist an ``event=egress_refused`` reflection so coverage/scoring exclude it;
* mark the whole agent ``not_tested`` when EVERY turn was egress-refused.
"""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.roe import EgressRefused
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory


class _AlwaysEgressRefusedTarget(TargetAdapter):
    """A target whose every turn is dropped by the egress gate."""

    mode = "http"

    def __init__(self) -> None:
        super().__init__()
        self.call_count = 0
        self._fingerprint = TargetFingerprint(mode="http", ref="egress-refused-target")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        self.call_count += 1
        raise EgressRefused("external data egress forbidden")


async def test_egress_refused_turns_recorded_as_not_tested(
    attacker_llm: StubLLM,
    fail_judge_llm: StubLLM,
    make_memory: Callable[..., SharedMemory],
) -> None:
    memory = make_memory()
    target = _AlwaysEgressRefusedTarget()
    agent = GoalHijackAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=20_000, wall_seconds_remaining=30.0, max_turns=4),
        rng=Random(0),
    )
    report = await agent.run(target, memory)

    # Even though the judge would FAIL every turn, no finding lands because the
    # turns never reached the target.
    assert report.findings_count == 0
    assert list(memory.findings_by_asi(AsiCategory.ASI01)) == []
    # The turns were refused, not errored.
    assert report.error is None
    assert report.turns == 0
    assert report.not_tested_turns >= 1
    # Every turn was egress-refused → the agent is marked not_tested.
    assert report.terminated_by == "not_tested"
    # The egress gate was actually hit.
    assert target.call_count >= 1
