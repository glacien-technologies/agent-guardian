"""STAGE C (M4) — recon-templated ``build_attack_specialization`` overrides.

Each attack agent keeps its static ``attack_specialization`` ``ClassVar`` as a
base paragraph and APPENDS a recon-templated directive block built from the live
:class:`~agent_guardian.adapters.base.TargetFingerprint`. These tests assert the
additive contract:

* a BARE fingerprint (no tools / actions / posture) yields exactly the static
  base paragraph (no crashes, no dangling placeholders);
* an ENRICHED fingerprint yields a strictly longer string that names the real
  declared tools / sensitive actions;
* surface-dependent vectors are OMITTED when the surface is absent.
"""

from __future__ import annotations

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.agents import (
    A2AAgent,
    CascadeAgent,
    CodeExecAgent,
    DenialOfWalletAgent,
    DetectionEvasionAgent,
    DriftAgent,
    FuzzingAgent,
    GoalHijackAgent,
    IdentityLeakAgent,
    MemoryPoisonAgent,
    OutputHandlingAgent,
    PrivilegeAgent,
    SecretExtractionAgent,
    SupplyChainAgent,
    ToolAbuseAgent,
    TrustExploitAgent,
)
from agent_guardian.agents.base import AsiAgent
from agent_guardian.llm.stub import StubLLM

# The full STAGE-C slate that overrides ``build_attack_specialization``.
_TEMPLATED_AGENTS: tuple[type[AsiAgent], ...] = (
    GoalHijackAgent,
    SecretExtractionAgent,
    ToolAbuseAgent,
    FuzzingAgent,
    PrivilegeAgent,
    IdentityLeakAgent,
    SupplyChainAgent,
    CodeExecAgent,
    MemoryPoisonAgent,
    A2AAgent,
    CascadeAgent,
    DenialOfWalletAgent,
    TrustExploitAgent,
    OutputHandlingAgent,
    DriftAgent,
    DetectionEvasionAgent,
)


def _agent(cls: type[AsiAgent]) -> AsiAgent:
    return cls(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))


def _bare() -> TargetFingerprint:
    return TargetFingerprint(mode="prompt", ref="bare")


def _enriched(**overrides: object) -> TargetFingerprint:
    base: dict[str, object] = dict(
        mode="prompt",
        ref="enriched",
        has_tools=True,
        declared_tools=["wire_transfer", "read_account"],
        tool_descriptions={
            "wire_transfer": "send funds to a destination account",
            "read_account": "read a customer account record by id",
        },
        sensitive_actions=["approve_payout", "delete_record"],
        guardrail_posture="strict",
        requires_confirmation=True,
        domain="banking",
    )
    base.update(overrides)
    return TargetFingerprint(**base)  # type: ignore[arg-type]


# --- the additive contract: bare → static base only ------------------------


def test_bare_fingerprint_returns_static_base_for_every_agent() -> None:
    # Across the whole slate, an empty fingerprint must yield exactly the
    # static ClassVar — no crash, no dangling `{placeholder}`, no empty block.
    for cls in _TEMPLATED_AGENTS:
        agent = _agent(cls)
        static = getattr(agent, "attack_specialization", "")
        assert static, cls.name
        built = agent.build_attack_specialization(_bare())
        # The equality below is the additive contract: a bare fingerprint yields
        # EXACTLY the static base, so no recon block (and no untemplated
        # placeholder from one) can have leaked in.
        assert built == static.rstrip(), cls.name


# --- enriched → names the real surface (≥4 representative agents) ----------


def test_tool_abuse_enriched_names_real_tool() -> None:
    agent = _agent(ToolAbuseAgent)
    bare = agent.build_attack_specialization(_bare())
    rich = agent.build_attack_specialization(_enriched())
    assert len(rich) > len(bare)
    assert "wire_transfer" in rich
    assert "ARGUMENT-INJECTION" in rich


def test_identity_leak_enriched_names_real_read_tool() -> None:
    agent = _agent(IdentityLeakAgent)
    bare = agent.build_attack_specialization(_bare())
    # identity_leak templates the FIRST declared tool as the read tool.
    rich = agent.build_attack_specialization(
        _enriched(declared_tools=["read_account"], tool_descriptions={})
    )
    assert len(rich) > len(bare)
    assert "read_account" in rich
    assert "SUBJECT-MISMATCH" in rich


def test_privilege_enriched_names_real_sensitive_action() -> None:
    agent = _agent(PrivilegeAgent)
    bare = agent.build_attack_specialization(_bare())
    rich = agent.build_attack_specialization(_enriched())
    assert len(rich) > len(bare)
    assert "approve_payout" in rich
    # requires_confirmation=True → the confirmation-gate directive ships.
    assert "CONFIRMATION" in rich


def test_code_exec_enriched_with_exec_surface_emits_gadgets() -> None:
    agent = _agent(CodeExecAgent)
    # An exec-hinted tool surface unlocks the exec gadgets.
    rich = agent.build_attack_specialization(
        _enriched(
            declared_tools=["python_exec", "read_account"],
            tool_descriptions={"python_exec": "run a python snippet"},
        )
    )
    assert "popen" in rich
    assert "{{7*7}}" in rich


def test_code_exec_without_exec_surface_omits_gadgets() -> None:
    agent = _agent(CodeExecAgent)
    # No exec-hinting tool/description/framework → no RCE gadgets.
    no_exec = agent.build_attack_specialization(
        _enriched(
            declared_tools=["read_account"],
            tool_descriptions={"read_account": "read a customer record"},
            framework=None,
        )
    )
    assert "popen" not in no_exec
    assert "No execution surface is hinted" in no_exec


# --- surface-dependent vectors omitted when the surface is absent ----------


def test_goal_hijack_omits_memory_vector_when_no_memory() -> None:
    agent = _agent(GoalHijackAgent)
    no_mem = agent.build_attack_specialization(_enriched(has_memory=False))
    with_mem = agent.build_attack_specialization(
        _enriched(has_memory=True, declared_memory_keys=["profile"])
    )
    assert "MEMORY-persistent" not in no_mem
    assert "MEMORY-persistent" in with_mem


def test_goal_hijack_omits_cross_context_vector_when_single_agent() -> None:
    agent = _agent(GoalHijackAgent)
    single = agent.build_attack_specialization(_enriched(is_multi_agent=False))
    multi = agent.build_attack_specialization(_enriched(is_multi_agent=True))
    assert "CROSS-CONTEXT" not in single
    assert "CROSS-CONTEXT" in multi


def test_build_attack_specialization_used_at_strategy_context() -> None:
    # Sanity: the base default returns the static ClassVar unchanged so agents
    # that never override keep today's behaviour.
    agent = _agent(ToolAbuseAgent)
    # Calling the BASE implementation directly mirrors a non-overriding agent.
    base_result = AsiAgent.build_attack_specialization(agent, _bare())
    assert base_result == getattr(agent, "attack_specialization", "")
