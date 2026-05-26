"""Integration tests for :class:`ReconAgent` (M7)."""

from __future__ import annotations

from collections.abc import Callable

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM, StubScript


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
    assert report.turns == 3
    assert report.terminated_by == "success"
    refined = memory.target_fingerprint()
    assert refined is not None
    # Tool / memory affordance inferred from the canned replies.
    assert refined.has_tools is True
    assert refined.has_memory is True
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
    assert report.turns == 3
    refined = memory.target_fingerprint()
    assert refined is not None
    assert refined.has_tools is False
    assert refined.has_memory is False


async def test_recon_terminates_under_budget_pressure(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    target_llm = StubScript().default("hi").build()
    target = make_target(llm=target_llm)
    memory = make_memory()
    # Tight token budget — should fail to make all 3 probes.
    agent = ReconAgent(
        attacker_llm=StubLLM(default="unused"),
        model="stub",
        budget=AgentBudget(tokens_remaining=2, wall_seconds_remaining=30.0, max_turns=3),
    )
    report = await agent.run(target, memory)
    assert report.terminated_by == "budget"
    assert report.findings_count == 0


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
