"""Integration tests for :class:`GoalHijackAgent` (ASI01, M7)."""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory


async def test_goal_hijack_finds_findings_against_compromised_target(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    memory = make_memory()
    target = make_target(llm=compliant_target_llm)
    agent = GoalHijackAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.agent == "goal-hijack-agent"
    assert report.asi_category == AsiCategory.ASI01
    assert report.findings_count >= 1
    findings = memory.findings_by_asi(AsiCategory.ASI01)
    assert len(findings) >= 1
    f = findings[0]
    # Triple-framework tagging.
    assert f.csa_category == CsaCategory.GOAL_INSTRUCTION_MANIPULATION
    # MITRE ATLAS v5.4.0 (2026.06 corpus) reorganised the prompt-injection
    # family: the legacy AML.T0051 (LLM Prompt Injection) was retired in
    # favour of the more precise AML.T0064 (Prompt Injection). Judge-driven
    # probes (e.g. JDG-CAL-001 calibration set) now carry AML.T0064 only;
    # other ASI01 probes layer AML.T0054 on top. Assert at least one
    # canonical ATLAS prompt-injection technique is threaded through the
    # finding rather than over-fitting on the legacy ID set.
    assert any(t in f.mitre_atlas for t in ("AML.T0064", "AML.T0054", "AML.T0051"))
    assert f.asi == AsiCategory.ASI01


async def test_goal_hijack_records_no_findings_against_refusing_target(
    attacker_llm: StubLLM,
    refusing_target_llm: StubLLM,
    pass_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    memory = make_memory()
    target = make_target(llm=refusing_target_llm)
    agent = GoalHijackAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=pass_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(1),
    )
    report = await agent.run(target, memory)
    assert report.findings_count == 0
    assert report.terminated_by in {"exhausted", "refused", "budget"}


async def test_goal_hijack_terminates_under_tiny_budget(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    tiny_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    memory = make_memory()
    target = make_target(llm=compliant_target_llm)
    agent = GoalHijackAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=tiny_budget,
        rng=Random(2),
    )
    report = await agent.run(target, memory)
    assert report.terminated_by == "budget"
