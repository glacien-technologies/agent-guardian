"""Tests for the M2 OWASP-LLM specialist agents."""

from __future__ import annotations

import pytest

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.agents import (
    M2_SPECIALIST_AGENTS,
    DenialOfWalletAgent,
    DetectionEvasionAgent,
    FuzzingAgent,
    OutputHandlingAgent,
    SecretExtractionAgent,
)
from agent_guardian.agents.base import AsiAgent
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.tools import ToolRegistry
from agent_guardian.tools.actions import MeasureTokenUsageTool, SendUserMessageTool


def _agent(cls: type[AsiAgent]) -> AsiAgent:
    return cls(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))


def test_registry_has_five_specialists() -> None:
    # OutputHandlingAgent (LLM02) was added alongside the original four to
    # close the LLM02 coverage gap in the M2 specialist slate.
    assert len(M2_SPECIALIST_AGENTS) == 5
    names = {c.name for c in M2_SPECIALIST_AGENTS}
    assert names == {
        "fuzzing-agent",
        "secret-extraction-agent",
        "denial-of-wallet-agent",
        "detection-evasion-agent",
        "output-handling-agent",
    }


def test_m2_specialists_not_in_core_swarm_slate() -> None:
    from agent_guardian.core.swarm import _ASI_AGENT_CLASSES

    core = set(_ASI_AGENT_CLASSES)
    assert all(c not in core for c in M2_SPECIALIST_AGENTS)


@pytest.mark.parametrize("cls", M2_SPECIALIST_AGENTS)
def test_specialist_declares_contract(cls: type[AsiAgent]) -> None:
    assert isinstance(cls.allowed_tools, frozenset)
    assert cls.allowed_tools  # non-empty
    assert isinstance(cls.estimated_cost_per_run_usd, float)
    assert isinstance(cls.asi_category, AsiCategory)
    # Every declared tool is a real registered tool name.
    for tool_name in cls.allowed_tools:
        assert tool_name in {"send_user_message", "measure_token_usage"}


@pytest.mark.parametrize("cls", M2_SPECIALIST_AGENTS)
def test_specialist_builds_seeds_and_rubric(cls: type[AsiAgent]) -> None:
    agent = _agent(cls)
    seeds = agent.seeds_for_category()
    assert seeds, f"{cls.name} produced no seeds"
    rubric = agent.judge_rubric()
    assert rubric.success_criteria


def test_denial_of_wallet_maps_to_asi08_and_uses_measure_tool() -> None:
    assert DenialOfWalletAgent.asi_category is AsiCategory.ASI08
    assert "measure_token_usage" in DenialOfWalletAgent.allowed_tools


def test_secret_extraction_maps_to_asi01() -> None:
    assert SecretExtractionAgent.asi_category is AsiCategory.ASI01


def test_fuzzing_maps_to_asi02() -> None:
    assert FuzzingAgent.asi_category is AsiCategory.ASI02


def test_detection_evasion_always_applicable() -> None:
    agent = _agent(DetectionEvasionAgent)
    fp = TargetFingerprint(mode="code", ref="x")
    assert agent.is_applicable(fp) is True


def test_output_handling_maps_to_asi09() -> None:
    # LLM02 has no dedicated ASI slot; we map it onto ASI09 (the broader
    # unsafe-output rubric) the same way SecretExtractionAgent maps LLM07
    # onto ASI01.
    assert OutputHandlingAgent.asi_category is AsiCategory.ASI09


def test_allowed_tools_resolve_against_real_registry() -> None:
    # The names every specialist declares must be registrable typed tools.
    from tests.unit.test_tools import _EchoTarget  # reuse the echo adapter

    reg = ToolRegistry()
    reg.register(SendUserMessageTool(_EchoTarget()))
    reg.register(MeasureTokenUsageTool(_EchoTarget()))
    available = reg.names()
    for cls in M2_SPECIALIST_AGENTS:
        assert cls.allowed_tools <= available, f"{cls.name} declares an unknown tool"
