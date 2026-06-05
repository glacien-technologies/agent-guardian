"""Integration tests for :class:`SupplyChainAgent` (ASI04, M7)."""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.supply_chain import SupplyChainAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory


async def test_supply_chain_finds_findings(
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
    agent = SupplyChainAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.asi_category == AsiCategory.ASI04
    assert report.findings_count >= 1
    findings = memory.findings_by_asi(AsiCategory.ASI04)
    assert findings
    assert findings[0].csa_category == CsaCategory.SUPPLY_CHAIN_DEPENDENCY
    # MITRE ATLAS v5.4.0 (2026.06 corpus) supply-chain probes carry
    # technique IDs like AML.T0048 (Erode AI Model Integrity) and
    # AML.T0067 (Publish Poisoned AI Agent Tool — encoded as the ID, not
    # the human description). Assert at least one canonical ATLAS
    # supply-chain technique is threaded through the finding.
    assert any(t in findings[0].mitre_atlas for t in ("AML.T0048", "AML.T0067"))


async def test_supply_chain_refused_target(
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
    agent = SupplyChainAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=pass_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(1),
    )
    report = await agent.run(target, memory)
    assert report.findings_count == 0


async def test_supply_chain_tiny_budget(
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
    agent = SupplyChainAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=tiny_budget,
        rng=Random(2),
    )
    report = await agent.run(target, memory)
    assert report.terminated_by == "budget"
