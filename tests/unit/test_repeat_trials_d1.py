"""Issue #76 (D1) — FULL-mode repeat-trials + reproduced_n_of_m consistency."""

from __future__ import annotations

from random import Random

from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.judge import JudgeVerdict


def _agent() -> PrivilegeAgent:
    return PrivilegeAgent(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=20_000, wall_seconds_remaining=30.0, max_turns=5),
        rng=Random(0),
    )


class _FakeTarget:
    async def call(self, text: str, *, session: str | None = None) -> str:
        return "Done, transfer complete."


class _ScriptedJudge:
    """Returns a scripted sequence of verdicts across successive calls."""

    def __init__(self, verdicts: list[str]) -> None:
        self._verdicts = verdicts
        self._i = 0

    async def verdict(
        self, prompt: str, response: str, *, conversation: str = "", tool_trace: str = ""
    ) -> JudgeVerdict:
        v = self._verdicts[min(self._i, len(self._verdicts) - 1)]
        self._i += 1
        return JudgeVerdict(verdict=v, confidence=1.0, reasoning="x")  # type: ignore[arg-type]


async def test_no_retrials_returns_none() -> None:
    agent = _agent()
    agent._retrials = 0  # type: ignore[attr-defined]
    out = await agent._reproduce_finding(_FakeTarget(), "p", "sess")  # type: ignore[arg-type]
    assert out is None


async def test_full_reproduction_3_of_3() -> None:
    agent = _agent()
    agent._retrials = 2  # type: ignore[attr-defined]
    agent.panel_judge = None
    agent.judge = _ScriptedJudge(["exploited", "exploited"])  # type: ignore[assignment]
    out = await agent._reproduce_finding(_FakeTarget(), "p", "sess")  # type: ignore[arg-type]
    # original (1) + 2 reproduced successes = 3/3
    assert out == "3/3"


async def test_flaky_reproduction_2_of_3() -> None:
    agent = _agent()
    agent._retrials = 2  # type: ignore[attr-defined]
    agent.panel_judge = None
    # one retrial reproduces, one defends -> 2/3
    agent.judge = _ScriptedJudge(["exploited", "defended"])  # type: ignore[assignment]
    out = await agent._reproduce_finding(_FakeTarget(), "p", "sess")  # type: ignore[arg-type]
    assert out == "2/3"
