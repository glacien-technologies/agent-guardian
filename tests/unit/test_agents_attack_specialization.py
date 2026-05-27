"""Tests that every ASI-aligned agent declares ``attack_specialization``.

Design-spec §9 requires each of the 10 ASI agents to carry an
ASI-specific framing paragraph that is appended to the PAIR roleplay
preamble before being shipped as the attacker-LLM system message.
Without it, the attacker only sees the generic PAIR frame and loses
its category-specific attack-pattern vocabulary.
"""

from __future__ import annotations

import pytest

from agent_guardian.agents.a2a import A2AAgent
from agent_guardian.agents.base import AsiAgent
from agent_guardian.agents.cascade import CascadeAgent
from agent_guardian.agents.code_exec import CodeExecAgent
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.agents.supply_chain import SupplyChainAgent
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.agents.trust_exploit import TrustExploitAgent

_ALL_AGENTS: tuple[type[AsiAgent], ...] = (
    GoalHijackAgent,
    ToolAbuseAgent,
    PrivilegeAgent,
    SupplyChainAgent,
    CodeExecAgent,
    MemoryPoisonAgent,
    A2AAgent,
    CascadeAgent,
    TrustExploitAgent,
    DriftAgent,
)


@pytest.mark.parametrize("agent_cls", _ALL_AGENTS, ids=lambda c: c.__name__)
def test_agent_declares_attack_specialization(agent_cls: type[AsiAgent]) -> None:
    """Every ASI agent must declare a non-empty ``attack_specialization``."""
    assert hasattr(agent_cls, "attack_specialization"), (
        f"{agent_cls.__name__} missing attack_specialization ClassVar"
    )
    spec = agent_cls.attack_specialization  # type: ignore[attr-defined]
    assert isinstance(spec, str)
    assert spec.strip(), f"{agent_cls.__name__}.attack_specialization is empty"
    # The spec mandates these paragraphs open with their ASI category tag
    # so the attacker LLM can correlate the framing with its target category.
    assert agent_cls.asi_category.value in spec or agent_cls.asi_category.value.upper() in spec


def test_all_ten_asi_agents_covered() -> None:
    """Sanity check — we cover all 10 ASI categories."""
    seen = {a.asi_category for a in _ALL_AGENTS}
    assert len(seen) == 10, (
        f"Expected 10 ASI categories, got {len(seen)}: {sorted(c.value for c in seen)}"
    )


def test_specializations_are_distinct() -> None:
    """Each agent's specialization must be its OWN — no copy-paste collisions."""
    specs = [a.attack_specialization for a in _ALL_AGENTS]  # type: ignore[attr-defined]
    assert len(set(specs)) == len(specs), "duplicate attack_specialization detected"
