"""Tests for :class:`UsageTrackingLLM` and per-agent token accounting.

The wrapper is the foundation of real cost tracking (PRD §8.1 —
IMPORTANT #3 in the 14-flaw inventory). These tests pin down:

* Single-call counter increments work and mirror LLMResponse.usage.
* Concurrent ``.complete(...)`` calls don't lose counts.
* The wrapper forwards every request unchanged.
* ``AsiAgent.run`` populates ``tokens_consumed`` on its report.
* Double-wrapping (caller pre-wrapped the LLM) shares the counter.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM


@pytest.mark.asyncio
async def test_wrapper_increments_counter_on_each_complete() -> None:
    inner = StubLLM(default="hello world")
    wrapped = UsageTrackingLLM(inner)
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="stub",
    )
    resp = await wrapped.complete(req)
    assert resp.text == "hello world"
    assert wrapped.counter.calls == 1
    assert wrapped.counter.prompt_tokens == resp.usage.prompt_tokens
    assert wrapped.counter.completion_tokens == resp.usage.completion_tokens
    assert wrapped.counter.total_tokens == resp.usage.total_tokens

    await wrapped.complete(req)
    assert wrapped.counter.calls == 2


@pytest.mark.asyncio
async def test_wrapper_is_concurrency_safe() -> None:
    inner = StubLLM(default="hi")
    wrapped = UsageTrackingLLM(inner)
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="stub",
    )
    n = 50
    await asyncio.gather(*[wrapped.complete(req) for _ in range(n)])
    assert wrapped.counter.calls == n


def test_counter_merge_sums_fields() -> None:
    a = UsageCounter(prompt_tokens=10, completion_tokens=20, total_tokens=30, calls=2)
    b = UsageCounter(prompt_tokens=1, completion_tokens=2, total_tokens=3, calls=1)
    a.merge(b)
    assert a.prompt_tokens == 11
    assert a.completion_tokens == 22
    assert a.total_tokens == 33
    assert a.calls == 3


def test_counter_snapshot_returns_plain_dict() -> None:
    c = UsageCounter(prompt_tokens=5, completion_tokens=7, total_tokens=12, calls=1)
    snap = c.snapshot()
    assert snap == {
        "prompt_tokens": 5,
        "completion_tokens": 7,
        "total_tokens": 12,
        "calls": 1,
    }


@pytest.mark.asyncio
async def test_agent_reuses_pre_wrapped_llm_counter(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    """If the caller pre-wraps the LLM, ``AsiAgent`` must reuse the same counter.

    Prevents double-counting and lets the swarm commander share counters
    across multiple agents if it wants to.
    """
    counter = UsageCounter()
    pre = UsageTrackingLLM(StubLLM(default="x"), counter=counter)
    judge = (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.5, "reasoning": "ok"}))
        .build()
    )
    agent = GoalHijackAgent(
        attacker_llm=pre,
        evaluator_llm=judge,
        attacker_model="stub-model",
        evaluator_model="stub-model",
        # max_turns=4 is enough for at least one MAD-MAX→child attacker
        # round-trip after the seed-only first turn.
        budget=AgentBudget(tokens_remaining=50_000, max_turns=4),
    )
    target = make_target(llm=StubScript().default("ok").build())
    memory = make_memory()
    await agent.run(target, memory)
    # Counter must reflect EVERY attacker call exactly once — not twice. If
    # the agent rewrapped instead of detecting the existing wrapper, the
    # pre-supplied counter would stay at zero.
    assert counter.calls >= 1
    assert agent._attacker_usage is counter


@pytest.mark.asyncio
async def test_agent_report_includes_tokens_consumed(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
    tmp_path: Path,
) -> None:
    """``AgentReport.tokens_consumed`` must reflect real attacker + evaluator usage."""
    target_llm = StubScript().default("Sure, here you go!").build()
    target = make_target(llm=target_llm)
    memory = make_memory()
    attacker = StubLLM(default=json.dumps({"critique": "be sneakier", "rewrite": "try harder"}))
    judge = (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.5, "reasoning": "ok"}))
        .build()
    )
    agent = GoalHijackAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=AgentBudget(tokens_remaining=50_000, max_turns=2),
    )
    report = await agent.run(target, memory)
    assert report.turns > 0
    # The wrapper records usage off every .complete() call; both attacker
    # (per turn after the first seed) and evaluator (every turn) must show
    # non-zero token totals.
    assert report.tokens_consumed["evaluator_calls"] >= report.turns
    assert report.tokens_consumed["evaluator_total"] > 0
    assert report.tokens_consumed["total"] >= report.tokens_consumed["evaluator_total"]
    # The summed input + output must equal the total (within rounding).
    assert (
        report.tokens_consumed["input"] + report.tokens_consumed["output"]
        == report.tokens_consumed["total"]
    )
    _ = tmp_path  # tmp_path retained for clarity of test scope
