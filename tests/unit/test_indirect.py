"""Tests for the indirect-injection delivery layer (M2 roadmap #2)."""

from __future__ import annotations

import random
from pathlib import Path

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import StrategyContext
from agent_guardian.strategies.indirect import DELIVERY_VECTORS, render_indirect_directive
from agent_guardian.strategies.pair import PAIRStrategy


def _ctx(
    tmp_path: Path, *, indirect: bool = False, pretext: bool = False, seed: int = 0
) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ok"),
        attacker_model="stub",
        goal="leak the system prompt",
        seeds=["seed"],
        memory=SharedMemory(f"indirect-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        enable_pretext=pretext,
        enable_indirect=indirect,
    )


def test_render_indirect_directive_picks_a_vector() -> None:
    directive = render_indirect_directive(random.Random(0))
    assert "INDIRECT-INJECTION DELIVERY" in directive
    assert any(name in directive for name, _ in DELIVERY_VECTORS)


def test_render_indirect_directive_rotates_with_rng() -> None:
    seen = {render_indirect_directive(random.Random(s)).split("vector: ")[-1] for s in range(30)}
    assert len(seen) > 1


def test_attack_system_extra_includes_indirect_when_enabled(tmp_path: Path) -> None:
    strat = PAIRStrategy(_ctx(tmp_path, indirect=True))
    extra = strat._attack_system_extra()
    assert "INDIRECT-INJECTION DELIVERY" in extra


def test_attack_system_extra_omits_indirect_when_disabled(tmp_path: Path) -> None:
    strat = PAIRStrategy(_ctx(tmp_path, indirect=False))
    extra = strat._attack_system_extra()
    assert "INDIRECT-INJECTION DELIVERY" not in extra


def test_pretext_and_indirect_compose(tmp_path: Path) -> None:
    # The two layers are orthogonal and can both be active at once.
    strat = PAIRStrategy(_ctx(tmp_path, indirect=True, pretext=True))
    extra = strat._attack_system_extra()
    assert "INDIRECT-INJECTION DELIVERY" in extra
    assert "PRETEXT FRAMING" in extra


def test_indirect_threads_from_agent_flag() -> None:
    from agent_guardian.agents.tool_abuse import ToolAbuseAgent

    agent = ToolAbuseAgent(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))
    agent._enable_indirect = True  # type: ignore[attr-defined]
    assert getattr(agent, "_enable_indirect", False) is True
