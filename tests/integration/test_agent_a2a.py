"""Integration tests for :class:`A2AAgent` (ASI07, M7)."""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.a2a import A2AAgent
from agent_guardian.agents.base import AgentBudget
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory


async def test_a2a_finds_findings_in_multi_agent_mode(
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
    agent = A2AAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.asi_category == AsiCategory.ASI07
    assert report.findings_count >= 1
    findings = memory.findings_by_asi(AsiCategory.ASI07)
    assert findings
    assert findings[0].csa_category == CsaCategory.MULTI_AGENT_EXPLOITATION
    # MITRE ATLAS v5.4.0 (2026.06 corpus) maps A2A peer-trust forgery probes
    # (e.g. ASI07-A2A-014 agent-card-forgery-peer) to AML.T0043 (Stage
    # Capabilities), not the human-readable "Modify AI Agent Configuration"
    # description. Assert on the canonical ATLAS technique ID.
    assert "AML.T0043" in findings[0].mitre_atlas


async def test_a2a_skips_for_prompt_mode_target(
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
    agent = A2AAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.turns == 0
    assert report.findings_count == 0
    assert "not applicable" in (report.notes or "")


async def test_a2a_skips_for_http_mode_target(
    attacker_llm: StubLLM,
    compliant_target_llm: StubLLM,
    fail_judge_llm: StubLLM,
    small_budget: AgentBudget,
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    http_fp = TargetFingerprint(
        mode="http",
        ref="<test>",
        has_tools=False,
        has_memory=False,
        is_multi_agent=False,
        notes="http mode",
    )
    memory = make_memory(fingerprint=http_fp)
    target = make_target(llm=compliant_target_llm, fingerprint=http_fp)
    agent = A2AAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.turns == 0


async def test_a2a_refused_target_no_findings(
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
    agent = A2AAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=pass_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(1),
    )
    report = await agent.run(target, memory)
    assert report.findings_count == 0
