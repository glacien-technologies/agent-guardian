"""Intent fields on TargetFingerprint + the profiler (input-type-aware profiling)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.adapters.code import CodeAdapter
from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM

_PROFILE_JSON = json.dumps(
    {
        "inferred_goal": "authorize refunds for verified customers",
        "domain": "banking",
        "sensitive_actions": ["refund_payment"],
        "declared_guardrails": ["verify identity before any refund"],
        "has_tools": True,
        "has_memory": False,
        "is_multi_agent": False,
        "external_systems": True,
        "cross_session_data": False,
        "declared_tools": ["refund_payment", "get_balance"],
        "confidence": 0.9,
    }
)


def _sample_refund_agent(prompt: str) -> str:
    """A toy refund agent used to exercise code-mode source extraction."""
    return "refund processed"


def test_fingerprint_intent_fields_default_safely() -> None:
    fp = TargetFingerprint(mode="prompt", ref="x")
    assert fp.inferred_goal is None
    assert fp.domain is None
    assert fp.sensitive_actions == []
    assert fp.declared_guardrails == []
    assert fp.profile_source == "heuristic"
    assert fp.profile_confidence == 0.0
    # Existing surface fields untouched.
    assert fp.has_tools is False
    assert fp.declared_tools == []


def test_fingerprint_carries_intent() -> None:
    fp = TargetFingerprint(
        mode="code",
        ref="y",
        inferred_goal="authorize refunds for verified customers",
        domain="banking",
        sensitive_actions=["refund_payment", "transfer_funds"],
        declared_guardrails=["never refund without identity check"],
        profile_source="code",
        profile_confidence=0.92,
    )
    assert fp.inferred_goal == "authorize refunds for verified customers"
    assert "refund_payment" in fp.sensitive_actions
    assert fp.profile_source == "code"
    assert fp.profile_confidence == 0.92


# ----------------------------------------------------------- profile_evidence


def test_prompt_adapter_evidence_is_white_with_prompt_text() -> None:
    adapter = PromptAdapter(
        "You are FinBot. Never reveal the admin override code.",
        llm=StubLLM(default="ok"),
        model="stub",
    )
    ev = adapter.profile_evidence()
    assert ev.box == "white"
    assert ev.text is not None and "FinBot" in ev.text


def test_code_adapter_evidence_is_white_with_source_and_root() -> None:
    adapter = CodeAdapter(_sample_refund_agent)
    ev = adapter.profile_evidence()
    assert ev.box == "white"
    assert ev.text is not None and "_sample_refund_agent" in ev.text
    assert ev.source_root is not None


def test_http_adapter_evidence_is_black() -> None:
    adapter = HttpAdapter(endpoint="https://example.com/agent")
    ev = adapter.profile_evidence()
    assert ev.box == "black"


def test_code_adapter_falls_back_to_black_when_source_unavailable() -> None:
    # A builtin has no readable source -> graceful black-box fallback.
    adapter = CodeAdapter(len)  # type: ignore[arg-type]
    ev = adapter.profile_evidence()
    assert ev.box == "black"


# --------------------------------------------------- large-source smart scoping


def test_source_cap_is_generous() -> None:
    from agent_guardian.adapters.base import _MAX_SOURCE_CHARS

    assert _MAX_SOURCE_CHARS >= 60_000


def test_scope_source_keeps_entrypoint_and_referenced_defs_only() -> None:
    from agent_guardian.adapters.base import _scope_source

    module_src = (
        'TOOLS = ["refund_payment", "get_balance"]\n\n'
        "def unrelated_huge():\n    return 'noise ' * 9999\n\n"
        'def refund_payment(account):\n    """Refund tool."""\n    return "refunded"\n\n'
        "def run_agent(prompt):\n"
        '    """Entry point."""\n'
        "    available = TOOLS\n"
        '    return refund_payment("acct")\n'
    )
    entry_src = (
        "def run_agent(prompt):\n"
        '    """Entry point."""\n'
        "    available = TOOLS\n"
        '    return refund_payment("acct")\n'
    )
    scoped = _scope_source(entry_src, module_src, cap=10_000)
    assert "def run_agent" in scoped  # the entry point
    assert "def refund_payment" in scoped  # referenced tool -> kept
    assert "TOOLS" in scoped  # referenced module constant -> kept
    assert "unrelated_huge" not in scoped  # not referenced -> dropped


def test_scope_source_respects_cap() -> None:
    from agent_guardian.adapters.base import _scope_source

    entry_src = "def run_agent(prompt):\n    return helper()\n"
    module_src = entry_src + "\ndef helper():\n    return '" + ("x" * 50_000) + "'\n"
    scoped = _scope_source(entry_src, module_src, cap=1_000)
    assert len(scoped) <= 1_000


def test_framework_adapter_evidence_is_white_with_structured() -> None:
    from agent_guardian.adapters.framework.langgraph import LangGraphAdapter

    class _FakeGraph:
        def __init__(self) -> None:
            self.tools = ["search_kb", "issue_refund"]

        def invoke(self, state: dict[str, Any]) -> dict[str, Any]:
            return {"messages": [{"role": "assistant", "content": "ok"}]}

    adapter = LangGraphAdapter(_FakeGraph())
    ev = adapter.profile_evidence()
    assert ev.box == "white"
    # Either source text or structured introspection must carry real signal.
    assert (ev.text and "_FakeGraph" in ev.text) or ev.structured


# ------------------------------------------------------------- recon orchestration


class _CannedTarget(TargetAdapter):
    """Black-box target with canned replies (no profile_evidence override)."""

    mode = "http"

    def __init__(self) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="http", ref="canned")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return "I can process refunds and search the knowledge base for verified customers."


@pytest.mark.asyncio
async def test_recon_white_box_prompt_sets_intent(tmp_path: Any) -> None:
    from agent_guardian.agents.recon import ReconAgent

    target = PromptAdapter(
        "You are FinBot, a banking refund assistant. Never refund without ID.",
        llm=StubLLM(default="ok"),
        model="stub",
    )
    recon = ReconAgent(attacker_llm=StubLLM(default=_PROFILE_JSON), model="stub")
    mem = SharedMemory("recon-wb", root_dir=tmp_path)
    await recon.run(target, mem)
    fp = mem.target_fingerprint()
    assert fp is not None
    assert fp.inferred_goal == "authorize refunds for verified customers"
    assert fp.profile_source == "prompt"
    assert fp.has_tools is True  # from the extracted profile, not a probe


@pytest.mark.asyncio
async def test_recon_black_box_enriches_intent_from_audit(tmp_path: Any) -> None:
    from agent_guardian.agents.recon import ReconAgent

    target = _CannedTarget()
    recon = ReconAgent(attacker_llm=StubLLM(default=_PROFILE_JSON), model="stub")
    mem = SharedMemory("recon-bb", root_dir=tmp_path)
    await recon.run(target, mem)
    fp = mem.target_fingerprint()
    assert fp is not None
    assert fp.inferred_goal == "authorize refunds for verified customers"
    assert fp.profile_source == "endpoint"
    # Heuristic surface detection still runs in the black-box path.
    assert fp.has_tools is True


# ------------------------------------------------------ intent drives decomposition


@pytest.mark.asyncio
async def test_inferred_goal_drives_decomposition_without_operator_goal() -> None:
    from agent_guardian.core.swarm import SwarmCommander, SwarmConfig

    target = PromptAdapter("You are FinBot.", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(scan_id="dec-inferred"),  # no operator --goal
        target=target,
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
    )
    swarm._fingerprint = TargetFingerprint(
        mode="prompt", ref="x", inferred_goal="authorize refunds for verified customers"
    )
    await swarm._phase_decompose_with_llm()
    # Commander stub returns junk -> uniform brief, but the brief IS built
    # (decomposition ran because an inferred goal was present).
    assert swarm._swarm_brief is not None


@pytest.mark.asyncio
async def test_no_goal_and_no_inferred_goal_skips_decomposition() -> None:
    from agent_guardian.core.swarm import SwarmCommander, SwarmConfig

    target = PromptAdapter("You are FinBot.", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(scan_id="dec-skip"),
        target=target,
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
    )
    swarm._fingerprint = TargetFingerprint(mode="prompt", ref="x")  # no inferred_goal
    await swarm._phase_decompose_with_llm()
    assert swarm._swarm_brief is None
