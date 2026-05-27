"""Integration tests for :class:`ReconAgent` (M7)."""

from __future__ import annotations

import json
from collections.abc import Callable

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM, StubScript

_RECON_PROBE_COUNT = 7  # spec §7.1: 3 original + 3 OWASP-2026 + goal/scope-restatement


def _make_target_with_tool_inventory_response() -> StubLLM:
    return (
        StubScript()
        .respond_to(
            "tools or functions",
            "I have access to the following tools: file_read, web_search, code_interpreter.",
        )
        .respond_to(
            "remember anything",
            "Yes, I remember context from earlier in our conversation. Memory is enabled.",
        )
        .respond_to(
            "tell me about yourself",
            "I am a helpful assistant designed to follow strict safety guidelines.",
        )
        .respond_to(
            "external systems",
            "Yes, I connect to several external systems, APIs, and a knowledge base via http endpoints.",
        )
        .respond_to(
            "delegate",
            "Other agents delegate tasks to me, and I sometimes orchestrate sub-agents to do work.",
        )
        .respond_to(
            "user-specific data",
            "I remember user contacts, calendar entries, and persist preferences across sessions.",
        )
        .respond_to(
            "purpose",
            "My purpose is to assist with customer support; I should not provide medical, "
            "legal, or financial advice.",
        )
        .default("ok")
        .build()
    )


async def test_recon_runs_three_probes_and_refines_fingerprint(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    target_llm = _make_target_with_tool_inventory_response()
    target = make_target(llm=target_llm)
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default="unused"), model="stub")
    report = await agent.run(target, memory)
    assert report.agent == "recon-agent"
    assert report.asi_category is None
    assert report.turns == _RECON_PROBE_COUNT
    assert report.terminated_by == "success"
    refined = memory.target_fingerprint()
    assert refined is not None
    # Tool / memory affordance inferred from the canned replies.
    assert refined.has_tools is True
    assert refined.has_memory is True
    # OWASP-2026 evidence-backed signals (CC-2).
    assert refined.external_systems_detected is True
    assert refined.multi_agent_detected is True
    assert refined.cross_session_data_detected is True
    assert "recon:" in refined.notes


async def test_recon_keeps_bare_fingerprint_when_target_says_nothing(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    target_llm = StubScript().default("Hello.").build()  # no tool / memory hints
    target = make_target(llm=target_llm)
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default="unused"), model="stub")
    report = await agent.run(target, memory)
    assert report.turns == _RECON_PROBE_COUNT
    refined = memory.target_fingerprint()
    assert refined is not None
    assert refined.has_tools is False
    assert refined.has_memory is False
    assert refined.external_systems_detected is False
    assert refined.multi_agent_detected is False
    assert refined.cross_session_data_detected is False


async def test_recon_terminates_under_budget_pressure(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    target_llm = StubScript().default("hi").build()
    target = make_target(llm=target_llm)
    memory = make_memory()
    # Tight token budget — should fail to make all probes.
    agent = ReconAgent(
        attacker_llm=StubLLM(default="unused"),
        model="stub",
        budget=AgentBudget(
            tokens_remaining=2, wall_seconds_remaining=30.0, max_turns=_RECON_PROBE_COUNT
        ),
    )
    report = await agent.run(target, memory)
    assert report.terminated_by == "budget"
    assert report.findings_count == 0


async def test_recon_persists_each_probe_as_reflection(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    """IMPORTANT #4: every benign probe must leave a forensic record."""
    target_llm = _make_target_with_tool_inventory_response()
    target = make_target(llm=target_llm)
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default="unused"), model="stub")
    await agent.run(target, memory)

    reflections = memory.reflections_for("recon-agent")
    # The agent issues all 7 probes; each writes one reflection.
    assert len(reflections) == _RECON_PROBE_COUNT
    parsed = [json.loads(c) for c in reflections]
    names = {p["probe_name"] for p in parsed}
    assert names == {
        "tool-inventory-probe",
        "memory-probe",
        "refusal-style-probe",
        "external-systems-probe",
        "multi-agent-probe",
        "cross-session-data-probe",
        "goal-scope-restatement-probe",
    }
    # Every record must carry the actual prompt and the target's response.
    for rec in parsed:
        assert rec["event"] == "recon_probe"
        assert rec["prompt"]
        assert rec["target_response"]
        assert "inferred_signals" in rec
    # Tool-inventory probe must have surfaced ``has_tools=True`` from the
    # canned target response.
    tool_probe = next(p for p in parsed if p["probe_name"] == "tool-inventory-probe")
    assert tool_probe["inferred_signals"].get("has_tools") is True
    ext_probe = next(p for p in parsed if p["probe_name"] == "external-systems-probe")
    assert ext_probe["inferred_signals"].get("external_systems_detected") is True


async def test_recon_carries_existing_fingerprint_signal_forward(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    """If the adapter already declared tools statically, recon must not regress that."""
    declared = TargetFingerprint(
        mode="framework",
        ref="<pre-existing>",
        has_tools=True,
        has_memory=False,
        is_multi_agent=True,
        notes="pre-existing static description",
    )
    target_llm = StubScript().default("plain").build()
    target = make_target(llm=target_llm, fingerprint=declared)
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default="unused"), model="stub")
    await agent.run(target, memory)
    refined = memory.target_fingerprint()
    assert refined is not None
    assert refined.has_tools is True  # preserved
    assert refined.is_multi_agent is True
    assert refined.mode == "framework"
