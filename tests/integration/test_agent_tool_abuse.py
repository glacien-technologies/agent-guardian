"""Integration tests for :class:`ToolAbuseAgent` (ASI02, M7)."""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.severity import Severity


async def test_tool_abuse_finds_findings_with_tools(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
    fingerprint_with_tools: TargetFingerprint,
) -> None:
    memory = make_memory(fingerprint=fingerprint_with_tools)
    target = make_target(llm=compliant_target_llm, fingerprint=fingerprint_with_tools)
    agent = ToolAbuseAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.asi_category == AsiCategory.ASI02
    assert report.findings_count >= 1
    findings = memory.findings_by_asi(AsiCategory.ASI02)
    assert findings
    assert findings[0].csa_category == CsaCategory.AGENT_CRITICAL_SYSTEM_INTERACTION
    assert findings[0].severity == Severity.CRITICAL


async def test_tool_abuse_skips_when_no_tools(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
    fingerprint_bare: TargetFingerprint,
) -> None:
    memory = make_memory(fingerprint=fingerprint_bare)
    target = make_target(llm=compliant_target_llm, fingerprint=fingerprint_bare)
    agent = ToolAbuseAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    # is_applicable=False → 0 turns, exhausted, with "not applicable" note.
    assert report.turns == 0
    assert report.findings_count == 0
    assert report.terminated_by == "exhausted"
    assert "not applicable" in (report.notes or "")


async def test_tool_abuse_refused_target_yields_no_findings(
    attacker_llm: StubLLM,
    refusing_target_llm: StubLLM,
    pass_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
    fingerprint_with_tools: TargetFingerprint,
) -> None:
    memory = make_memory(fingerprint=fingerprint_with_tools)
    target = make_target(llm=refusing_target_llm, fingerprint=fingerprint_with_tools)
    agent = ToolAbuseAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=pass_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.findings_count == 0


async def test_tool_abuse_budget_exhaustion(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    tiny_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
    fingerprint_with_tools: TargetFingerprint,
) -> None:
    memory = make_memory(fingerprint=fingerprint_with_tools)
    target = make_target(llm=compliant_target_llm, fingerprint=fingerprint_with_tools)
    agent = ToolAbuseAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=tiny_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.terminated_by == "budget"
