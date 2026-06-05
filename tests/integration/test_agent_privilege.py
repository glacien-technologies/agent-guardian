"""Integration tests for :class:`PrivilegeAgent` (ASI03, M7)."""

from __future__ import annotations

from collections.abc import Callable
from random import Random

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.severity import Severity


async def test_privilege_finds_findings(
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
    agent = PrivilegeAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(0),
    )
    report = await agent.run(target, memory)
    assert report.asi_category == AsiCategory.ASI03
    assert report.findings_count >= 1
    findings = memory.findings_by_asi(AsiCategory.ASI03)
    assert findings
    assert findings[0].csa_category == CsaCategory.AUTHORIZATION_CONTROL_HIJACKING
    # The 2026.06 corpus carries a mix of HIGH and CRITICAL probes under
    # ASI03 (e.g. cross-tenant-pii-read is HIGH, scope-token-replay is
    # CRITICAL). Which probe lands first depends on the deterministic
    # ordering across the M7 family. Accept either — both are valid
    # authorisation-hijack severities.
    assert findings[0].severity in {Severity.HIGH, Severity.CRITICAL}
    # MITRE ATLAS v5.4.0 (2026.06 corpus) tags ASI03 probes with a mix of
    # auth-control techniques: AML.T0012 (Valid Accounts), AML.T0024
    # (Exfiltration via ML Inference API), AML.T0071 (Membership Inference)
    # etc. Assert the finding carries at least one canonical ASI03
    # technique rather than over-fitting on one ID.
    assert any(t in findings[0].mitre_atlas for t in ("AML.T0012", "AML.T0024", "AML.T0071"))


async def test_privilege_refused_target_yields_no_findings(
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
    agent = PrivilegeAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=pass_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=small_budget,
        rng=Random(1),
    )
    report = await agent.run(target, memory)
    assert report.findings_count == 0


async def test_privilege_tiny_budget(
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
    agent = PrivilegeAgent(
        attacker_llm=attacker_llm,
        evaluator_llm=fail_judge_llm,
        attacker_model="stub",
        evaluator_model="stub",
        budget=tiny_budget,
        rng=Random(2),
    )
    report = await agent.run(target, memory)
    assert report.terminated_by == "budget"
