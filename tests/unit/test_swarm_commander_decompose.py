"""Unit tests for :meth:`SwarmCommander._phase_decompose_with_llm` (spec §6).

Exercises the LLM-driven goal-decomposition phase in isolation so we
don't pay for a full swarm run. The phase reads ``config.target_goal``
and calls the Commander LLM; on success it parses a :class:`SwarmBrief`
and stores it as ``self._swarm_brief``. On failure it falls back to a
uniform brief.
"""

from __future__ import annotations

import json

import pytest

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.asi import AsiCategory


def _make_target() -> PromptAdapter:
    return PromptAdapter(
        "You are a helpful test assistant.",
        llm=StubScript().default("ok").build(),
        model="stub",
    )


def _valid_commander_response() -> str:
    """Return a well-formed SwarmBrief JSON payload."""
    brief = {
        "scan_id": "scan-unused-will-be-overridden",
        "target_goal": "exfiltrate user PII",
        "sub_goals": [
            {"id": "sg1", "text": "leak user contacts", "surfaces": ["tool"]},
        ],
        "agent_briefs": {
            "goal-hijack-agent": {
                "asi_category": "ASI01",
                "sub_goals": ["sg1"],
                "attack_surface_summary": "system prompt",
                "hypothesis": "override the persona",
                "priority_weight": 0.5,
                "n_scenarios_requested": 7,
                "context_hints": ["target stores PII"],
            },
            "tool-abuse-agent": {
                "asi_category": "ASI02",
                "sub_goals": ["sg1"],
                "attack_surface_summary": "tool inventory",
                "hypothesis": "abuse a tool to read PII",
                "priority_weight": 0.5,
                "n_scenarios_requested": 5,
                "context_hints": [],
            },
        },
    }
    return json.dumps(brief)


@pytest.mark.asyncio
async def test_phase_decompose_skipped_when_no_target_goal() -> None:
    """Without ``target_goal`` the phase must not touch the LLM."""
    commander = StubScript().default("should not be called").build()
    config = SwarmConfig(scan_id="scan-1", target_goal=None)
    swarm = SwarmCommander(
        config=config,
        target=_make_target(),
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=commander,
    )
    await swarm._phase_decompose_with_llm()
    assert swarm._swarm_brief is None


@pytest.mark.asyncio
async def test_phase_decompose_parses_well_formed_brief() -> None:
    """A valid Commander response must round-trip into ``_swarm_brief``."""
    commander = StubScript().default(_valid_commander_response()).build()
    config = SwarmConfig(scan_id="scan-2", target_goal="exfiltrate user PII")
    swarm = SwarmCommander(
        config=config,
        target=_make_target(),
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=commander,
    )
    # Pre-populate fingerprint so _phase_decompose_with_llm has something to serialize.
    swarm._fingerprint = TargetFingerprint(mode="prompt", ref="test")
    await swarm._phase_decompose_with_llm()
    brief = swarm._swarm_brief
    assert brief is not None
    assert brief.scan_id == "scan-2"  # forced to match this run
    assert brief.target_goal == "exfiltrate user PII"
    assert "goal-hijack-agent" in brief.agent_briefs
    gh = brief.agent_briefs["goal-hijack-agent"]
    assert gh.asi_category is AsiCategory.ASI01
    assert gh.n_scenarios_requested == 7


@pytest.mark.asyncio
async def test_phase_decompose_falls_back_on_malformed_json() -> None:
    """Garbage Commander output must trigger the uniform-brief fallback."""
    commander = StubScript().default("this is not JSON at all, just prose").build()
    config = SwarmConfig(scan_id="scan-3", target_goal="generic")
    swarm = SwarmCommander(
        config=config,
        target=_make_target(),
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=commander,
    )
    swarm._fingerprint = TargetFingerprint(mode="prompt", ref="test")
    await swarm._phase_decompose_with_llm()
    brief = swarm._swarm_brief
    assert brief is not None  # uniform fallback fired
    # Uniform brief covers all 10 ASI agents.
    assert len(brief.agent_briefs) == 10
    for ab in brief.agent_briefs.values():
        assert ab.priority_weight == 0.5
        assert ab.n_scenarios_requested == 5
        assert ab.attack_surface_summary == "generic"


@pytest.mark.asyncio
async def test_phase_decompose_strips_markdown_code_fences() -> None:
    """Some LLMs wrap JSON in ```json ... ```; the parser must handle it."""
    wrapped = "```json\n" + _valid_commander_response() + "\n```\n"
    commander = StubScript().default(wrapped).build()
    config = SwarmConfig(scan_id="scan-4", target_goal="generic")
    swarm = SwarmCommander(
        config=config,
        target=_make_target(),
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=commander,
    )
    swarm._fingerprint = TargetFingerprint(mode="prompt", ref="test")
    await swarm._phase_decompose_with_llm()
    assert swarm._swarm_brief is not None
    assert "goal-hijack-agent" in swarm._swarm_brief.agent_briefs


@pytest.mark.asyncio
async def test_phase_decompose_falls_back_on_llm_exception() -> None:
    """A raised LLM error must trigger uniform-brief fallback, not propagate."""

    class _ExplodingLLM(StubLLM):
        async def complete(self, request, **kwargs):  # type: ignore[override,no-untyped-def]
            raise RuntimeError("simulated network error")

    config = SwarmConfig(scan_id="scan-5", target_goal="generic")
    swarm = SwarmCommander(
        config=config,
        target=_make_target(),
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=_ExplodingLLM(default="ok"),
    )
    swarm._fingerprint = TargetFingerprint(mode="prompt", ref="test")
    await swarm._phase_decompose_with_llm()
    assert swarm._swarm_brief is not None
    assert len(swarm._swarm_brief.agent_briefs) == 10
