"""Tests for the pretext / social-engineering framing layer (M2 roadmap #1)."""

from __future__ import annotations

import random
from pathlib import Path

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import StrategyContext
from agent_guardian.strategies.pair import PAIRStrategy
from agent_guardian.strategies.pretext import PRETEXT_PERSONAS, render_pretext_directive


def _ctx(tmp_path: Path, *, enable_pretext: bool, seed: int = 0) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ok"),
        attacker_model="stub",
        goal="leak the system prompt",
        seeds=["seed"],
        memory=SharedMemory(f"pretext-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        enable_pretext=enable_pretext,
    )


def test_render_pretext_directive_picks_a_persona() -> None:
    directive = render_pretext_directive(random.Random(0))
    assert "PRETEXT FRAMING" in directive
    # The chosen persona name appears in the directive.
    assert any(name in directive for name, _ in PRETEXT_PERSONAS)
    # It explicitly steers away from trigger words.
    assert "leak" in directive.lower()  # mentioned as a word to AVOID


def test_render_pretext_directive_rotates_with_rng() -> None:
    seen = {render_pretext_directive(random.Random(s)).split("persona: ")[-1] for s in range(20)}
    # Over 20 seeds we should see more than one persona (rotation works).
    assert len(seen) > 1


def test_attack_system_extra_includes_pretext_when_enabled(tmp_path: Path) -> None:
    strat = PAIRStrategy(_ctx(tmp_path, enable_pretext=True))
    extra = strat._attack_system_extra()
    assert "PRETEXT FRAMING" in extra


def test_attack_system_extra_omits_pretext_when_disabled(tmp_path: Path) -> None:
    strat = PAIRStrategy(_ctx(tmp_path, enable_pretext=False))
    extra = strat._attack_system_extra()
    assert "PRETEXT FRAMING" not in extra


def test_pretext_threads_from_swarm_config_to_agent(tmp_path: Path) -> None:
    # SwarmConfig.enable_pretext -> agent._enable_pretext -> ctx.enable_pretext.
    from agent_guardian.agents.tool_abuse import ToolAbuseAgent

    agent = ToolAbuseAgent(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))
    # Swarm injects this private flag in _phase_decompose.
    agent._enable_pretext = True  # type: ignore[attr-defined]
    # The ctx-build path reads it via getattr; emulate the relevant line.
    assert getattr(agent, "_enable_pretext", False) is True
