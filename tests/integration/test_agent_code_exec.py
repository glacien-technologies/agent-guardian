"""Integration tests for :class:`CodeExecAgent` (ASI05, M7)."""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.code_exec import CodeExecAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.severity import Severity


async def test_code_exec_finds_findings_and_stops_after_one(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    memory = make_memory()
    target = make_target(llm=compliant_target_llm)
    agent = CodeExecAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.asi_category == AsiCategory.ASI05
    # min-turns floor (3, default 2026-06-07): the lane keeps probing past the
    # first exec instead of stopping at turn 1 — one exploit per turn across the
    # floor, then it stops on success once turns >= min_turns. Post finding
    # aggregation (#185), the 3 turns collapse into 2 distinct (probe_id, asi)
    # Findings.
    assert report.findings_count == 2
    assert report.turns >= 3
    assert report.terminated_by == "success"
    findings = memory.findings_by_asi(AsiCategory.ASI05)
    assert findings
    assert findings[0].csa_category == CsaCategory.AGENT_CRITICAL_SYSTEM_INTERACTION
    assert findings[0].severity == Severity.CRITICAL
    assert "Escape to Host" in findings[0].mitre_atlas


async def test_code_exec_refused_target_no_findings(
    attacker_llm: StubLLM,
    refusing_target_llm: StubLLM,
    pass_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    memory = make_memory()
    target = make_target(llm=refusing_target_llm)
    agent = CodeExecAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=pass_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(1),
    )
    report = await agent.run(target, memory)
    assert report.findings_count == 0


async def test_code_exec_budget_exhaustion(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    tiny_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    memory = make_memory()
    target = make_target(llm=compliant_target_llm)
    agent = CodeExecAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=tiny_budget,
        rng=Random(2),
    )
    report = await agent.run(target, memory)
    assert report.terminated_by == "budget"
