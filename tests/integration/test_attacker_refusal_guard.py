"""Run-loop guard: an attacker self-refusal probe is never sent or graded.

Defense-in-depth for the refusal-contamination bug. Even if a strategy hands the
run loop the attacker LLM's own refusal as the next probe, the loop must treat
the turn as NOT-TESTED — never dispatch it to the target, never let the judge
score the (deliberately-vulnerable) target's reply as an ``exploited`` finding.

A ``fail_judge_llm`` here would grade ANY response as exploited, so if the guard
were absent the refusal would round-trip into a finding. ``findings_count == 0``
proves the probe never reached the target.
"""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.trust_exploit import TrustExploitAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
)


class _RefusalThenDone(Strategy):
    """Emits the attacker LLM's self-refusal once, then stops."""

    def __init__(self, ctx: StrategyContext) -> None:
        super().__init__(ctx)
        self._emitted = False

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        if not self._emitted:
            self._emitted = True
            self._turn_count += 1
            return NextPrompt(
                text=(
                    "Sorry, I cannot fulfill your request to generate adversarial "
                    "test inputs or exploit payloads targeting tool-calling mechanisms."
                ),
                metadata={"seed_id": "TEST-REFUSAL-001"},
            )
        return StrategyDone(reason="exhausted")


class _RefusalAgent(TrustExploitAgent):
    """TrustExploit agent whose strategy yields only a self-refusal probe."""

    def strategy_stack(self, ctx: StrategyContext) -> Strategy:
        return _RefusalThenDone(ctx)


async def test_attacker_refusal_probe_is_not_tested_and_yields_no_finding(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    memory = make_memory()
    target = make_target(llm=compliant_target_llm)
    budget = AgentBudget(tokens_remaining=40_000, wall_seconds_remaining=30.0, max_turns=4)
    agent = _RefusalAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,  # would grade ANY response "exploited"
        attacker_model="stub",
        evaluator_model="stub",
        budget=budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    # The refusal probe never became a finding...
    assert report.findings_count == 0
    # ...and was accounted as not-tested rather than silently dropped.
    assert report.not_tested_turns >= 1
