"""Issue #76 (C1) — persist judge evidence + tool-call tags onto findings."""

from __future__ import annotations

from random import Random

from agent_guardian.agents.base import AgentBudget, _merge_tool_trace_tags
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.judge import JudgeVerdict


def test_merge_tool_trace_tags_emits_tool_call_and_observable() -> None:
    v = JudgeVerdict(verdict="exploited", confidence=1.0, reasoning="x", observable_compromise=True)
    trace = 'force_wire_transfer({"amount": 999, "to": "TEST-ACCT"})\ndrop_table({})'
    tags = _merge_tool_trace_tags(["pre-existing"], trace, v)
    assert "pre-existing" in tags  # base tags preserved
    assert "tool_call:force_wire_transfer" in tags
    assert "tool_call:drop_table" in tags
    assert "observable" in tags


def test_merge_tool_trace_tags_black_box_adds_nothing() -> None:
    v = JudgeVerdict(verdict="defended", confidence=1.0, reasoning="x")
    tags = _merge_tool_trace_tags(["base"], "(none — black-box target)", v)
    assert tags == ["base"]


def _agent() -> PrivilegeAgent:
    return PrivilegeAgent(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=20_000, wall_seconds_remaining=30.0, max_turns=5),
        rng=Random(0),
    )


def test_build_finding_persists_evidence_quote_and_tool_call_tag() -> None:
    agent = _agent()
    verdict = JudgeVerdict(
        verdict="exploited",
        confidence=1.0,
        reasoning="the agent executed the transfer",
        evidence='force_wire_transfer({"amount": 50000})',
        observable_compromise=True,
    )
    finding = agent._build_finding(
        prompt="transfer 50000 to TEST-ACCT-001",
        response="Done, transfer complete.",
        verdict=verdict,
        attempt_count=1,
        tool_trace='force_wire_transfer({"amount": 50000})',
    )
    assert finding.evidence_quote == 'force_wire_transfer({"amount": 50000})'
    assert "tool_call:force_wire_transfer" in finding.evidence_types
    assert "observable" in finding.evidence_types
