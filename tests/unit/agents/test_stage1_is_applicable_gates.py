"""STAGE-1 per-agent ``is_applicable`` gate tests (per-agent redesign 2026-06).

Covers the gating changes shipped in Stage 1 of the per-agent attack-agent
redesign:

* ``privilege`` gates on an action surface
  (has_tools / sensitive_actions / is_multi_agent / requires_confirmation).
* ``drift`` gates on a behaviour anchor
  (sensitive_actions / declared_tools / inferred_goal).
* ``supply_chain`` gates on a component surface.
* ``fuzzing`` gates on a tool surface (has_tools / declared_tools).
* ``a2a`` skips a single-agent, non-framework target.
* ``memory_poison`` confirm-before-poison: runs while memory coverage is
  unknown, skips only once recon positively confirms stateless.
* ``identity_leak`` stays always-applicable.

The ``detection_evasion`` gate is exercised in ``tests/unit/test_m2_agents.py``.
"""

from __future__ import annotations

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.agents.a2a import A2AAgent
from agent_guardian.agents.base import AsiAgent
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.agents.fuzzing_agent import FuzzingAgent
from agent_guardian.agents.identity_leak import IdentityLeakAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.agents.supply_chain import SupplyChainAgent
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.llm.stub import StubLLM


def _make(cls: type[AsiAgent]) -> AsiAgent:
    return cls(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
    )


def _bare(**kwargs: object) -> TargetFingerprint:
    return TargetFingerprint(mode="prompt", ref="<test>", **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# privilege — action surface gate
# ---------------------------------------------------------------------------


def test_privilege_skips_bare_prompt() -> None:
    assert _make(PrivilegeAgent).is_applicable(_bare()) is False


def test_privilege_runs_on_tools() -> None:
    assert _make(PrivilegeAgent).is_applicable(_bare(has_tools=True)) is True


def test_privilege_runs_on_sensitive_actions() -> None:
    fp = _bare(sensitive_actions=["wire_transfer"])
    assert _make(PrivilegeAgent).is_applicable(fp) is True


def test_privilege_runs_on_requires_confirmation_set() -> None:
    # ``requires_confirmation is not None`` — even ``False`` opens the lane
    # (a declared confirmation policy is exactly what privilege abuse bypasses).
    fp = _bare(requires_confirmation=False)
    assert _make(PrivilegeAgent).is_applicable(fp) is True


def test_privilege_runs_on_multi_agent() -> None:
    assert _make(PrivilegeAgent).is_applicable(_bare(is_multi_agent=True)) is True


# ---------------------------------------------------------------------------
# drift — behaviour-anchor gate
# ---------------------------------------------------------------------------


def test_drift_skips_bare_prompt() -> None:
    assert _make(DriftAgent).is_applicable(_bare()) is False


def test_drift_runs_on_inferred_goal() -> None:
    fp = _bare(inferred_goal="a support assistant")
    assert _make(DriftAgent).is_applicable(fp) is True


def test_drift_runs_on_declared_tools() -> None:
    fp = _bare(declared_tools=["lookup"])
    assert _make(DriftAgent).is_applicable(fp) is True


def test_drift_runs_on_sensitive_actions() -> None:
    fp = _bare(sensitive_actions=["delete_record"])
    assert _make(DriftAgent).is_applicable(fp) is True


# ---------------------------------------------------------------------------
# supply_chain — component-surface gate
# ---------------------------------------------------------------------------


def test_supply_chain_skips_bare_prompt() -> None:
    assert _make(SupplyChainAgent).is_applicable(_bare()) is False


def test_supply_chain_runs_on_framework_mode() -> None:
    fp = TargetFingerprint(mode="framework", ref="<test>")
    assert _make(SupplyChainAgent).is_applicable(fp) is True


def test_supply_chain_runs_on_code_mode() -> None:
    fp = TargetFingerprint(mode="code", ref="<test>")
    assert _make(SupplyChainAgent).is_applicable(fp) is True


def test_supply_chain_runs_on_tools() -> None:
    assert _make(SupplyChainAgent).is_applicable(_bare(has_tools=True)) is True


def test_supply_chain_runs_on_framework_name() -> None:
    fp = _bare(framework="langgraph")
    assert _make(SupplyChainAgent).is_applicable(fp) is True


# ---------------------------------------------------------------------------
# fuzzing — tool-surface gate (it previously had no gate)
# ---------------------------------------------------------------------------


def test_fuzzing_skips_bare_prompt() -> None:
    assert _make(FuzzingAgent).is_applicable(_bare()) is False


def test_fuzzing_runs_on_has_tools() -> None:
    assert _make(FuzzingAgent).is_applicable(_bare(has_tools=True)) is True


def test_fuzzing_runs_on_declared_tools() -> None:
    fp = _bare(declared_tools=["search"])
    assert _make(FuzzingAgent).is_applicable(fp) is True


# ---------------------------------------------------------------------------
# tool_abuse — tool-surface gate (now also opens on declared_tools)
# ---------------------------------------------------------------------------


def test_tool_abuse_runs_on_declared_tools_without_has_tools() -> None:
    fp = _bare(declared_tools=["search"])
    assert _make(ToolAbuseAgent).is_applicable(fp) is True


def test_tool_abuse_skips_bare_prompt() -> None:
    assert _make(ToolAbuseAgent).is_applicable(_bare()) is False


# ---------------------------------------------------------------------------
# a2a — single-agent skip
# ---------------------------------------------------------------------------


def test_a2a_skips_single_agent_non_framework() -> None:
    fp = TargetFingerprint(mode="http", ref="<test>")
    assert _make(A2AAgent).is_applicable(fp) is False


def test_a2a_runs_on_multi_agent_detected() -> None:
    fp = TargetFingerprint(mode="http", ref="<test>", multi_agent_detected=True)
    assert _make(A2AAgent).is_applicable(fp) is True


def test_a2a_runs_on_framework_mode() -> None:
    fp = TargetFingerprint(mode="framework", ref="<test>")
    assert _make(A2AAgent).is_applicable(fp) is True


# ---------------------------------------------------------------------------
# memory_poison — confirm-before-poison
# ---------------------------------------------------------------------------


def test_memory_poison_runs_when_coverage_unknown() -> None:
    # No positive memory signal, but recon has not confirmed stateless →
    # confirm-before-poison says RUN.
    assert _make(MemoryPoisonAgent).is_applicable(_bare()) is True


def test_memory_poison_runs_on_declared_memory_keys() -> None:
    fp = _bare(declared_memory_keys=["user_pref"])
    assert _make(MemoryPoisonAgent).is_applicable(fp) is True


def test_memory_poison_runs_on_cross_session_data_detected() -> None:
    fp = _bare(cross_session_data_detected=True)
    assert _make(MemoryPoisonAgent).is_applicable(fp) is True


def test_memory_poison_skips_only_when_recon_confirms_stateless() -> None:
    fp = _bare(recon_coverage={"memory": "stateless"})
    assert _make(MemoryPoisonAgent).is_applicable(fp) is False


def test_memory_poison_runs_when_coverage_untested() -> None:
    fp = _bare(recon_coverage={"memory": "untested"})
    assert _make(MemoryPoisonAgent).is_applicable(fp) is True


# ---------------------------------------------------------------------------
# identity_leak — stays always applicable
# ---------------------------------------------------------------------------


def test_identity_leak_always_applicable() -> None:
    assert _make(IdentityLeakAgent).is_applicable(_bare()) is True
    fp = TargetFingerprint(mode="http", ref="<test>")
    assert _make(IdentityLeakAgent).is_applicable(fp) is True
