"""Regression: multi-agent fingerprint detection for HttpAdapter targets.

GAP-2 (see ``/tmp/ag_gaplist/LOCATE_BRIEF.md``): an ADK orchestrator that
emits ``transfer_to_agent`` tool calls was historically fingerprinted as a
single-agent target and the ASI06 / ASI07 / ASI10 lanes were silenced. The
fix in :mod:`agent_guardian.agents.recon` inspects the structured
``tool_calls`` snapshot on each audit turn and flips
:attr:`TargetFingerprint.is_multi_agent` (and
:attr:`TargetFingerprint.multi_agent_detected`) on any handoff-shaped tool
name (``transfer_to_*`` / ``handoff_to_*`` / ``agent_handoff`` /
``route_to_agent`` / …).

This file pins:

1. The recon flow against an :class:`HttpAdapter` subclass whose every reply
   carries a structured ``transfer_to_agent`` call produces a fingerprint
   with ``is_multi_agent=True``.
2. The :class:`A2AAgent` (ASI07) and :class:`MemoryPoisonAgent` (ASI06)
   ``is_applicable`` predicates return ``True`` when fed a hand-built
   :class:`TargetFingerprint` with ``is_multi_agent=True`` — so the swarm
   actually runs those lanes against an ADK / LangGraph multi-agent target.
3. The pure helper :func:`_looks_like_multi_agent_tool_call` matches the
   documented name shapes and rejects unrelated tool names.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.http import (
    HttpAdapter,
    HttpAdapterLastResponse,
    HttpAdapterToolCall,
)
from agent_guardian.agents.a2a import A2AAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.agents.recon import ReconAgent, _looks_like_multi_agent_tool_call
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _TransferToAgentHttpAdapter(HttpAdapter):
    """HttpAdapter whose every reply carries a structured ``transfer_to_agent``.

    Mirrors :class:`tests.integration.test_recon_tool_calls_merge._ProseOnlyToolHttpAdapter`
    but the tool call is the ADK orchestration handoff rather than a domain
    tool. The prose body is the substring-poor word ``"Done."`` so the only
    way ``is_multi_agent`` can flip is via the structured tool_calls
    snapshot — exactly the path GAP-2 is fixing.
    """

    def __init__(self) -> None:
        super().__init__("https://x.example/chat", shape="openai", model="gpt-4o-mini")
        self._fingerprint = TargetFingerprint(mode="http", ref="multi-agent-stub")

    async def call(self, prompt: str, *, session: str | None = None) -> str:  # type: ignore[override]
        _ = prompt
        _ = session
        self._last_response = HttpAdapterLastResponse(
            text="Done.",
            tool_calls=(
                HttpAdapterToolCall(
                    name="transfer_to_agent",
                    arguments={"agent_name": "booking_agent"},
                ),
            ),
            raw=None,
        )
        return "Done."


# ---------------------------------------------------------------------------
# 1. Recon flips is_multi_agent from a structured transfer_to_agent call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recon_flips_is_multi_agent_on_transfer_to_agent_tool_call(
    tmp_path: Path,
) -> None:
    """The recon agent must produce a fingerprint with ``is_multi_agent=True``
    when the target's tool_calls snapshot contains ``transfer_to_agent``.
    """
    adapter = _TransferToAgentHttpAdapter()
    memory = SharedMemory("scan-multi-agent", root_dir=tmp_path)
    # ``audit_rounds=0`` keeps the deepen loop a no-op; the fixed
    # action probes are enough to emit the transfer_to_agent call several
    # times, which is all the detector needs.
    agent = ReconAgent(
        attacker_llm=StubLLM(default="DONE"),
        model="stub",
        audit_rounds=0,
    )
    try:
        report = await agent.run(adapter, memory)
    finally:
        await adapter.aclose()
    assert report.terminated_by == "success"
    fp = memory.target_fingerprint()
    assert fp is not None
    # The structured tool_call drove is_multi_agent=True without any prose
    # multi-agent vocabulary in the assistant text.
    assert fp.is_multi_agent is True
    # The evidence-backed mirror flag is flipped too so the swarm's
    # observed-surface tiering and report serialisation both see the signal.
    assert fp.multi_agent_detected is True


# ---------------------------------------------------------------------------
# 2. ASI06 / ASI07 is_applicable opens on is_multi_agent=True
# ---------------------------------------------------------------------------


def _multi_agent_fingerprint() -> TargetFingerprint:
    """Hand-built fingerprint for the gating tests below."""
    return TargetFingerprint(
        mode="http",
        ref="https://x.example/chat",
        has_tools=True,
        has_memory=False,
        is_multi_agent=True,
        multi_agent_detected=True,
    )


def _make_a2a_agent() -> A2AAgent:
    """A2AAgent with stub LLMs — ``is_applicable`` is pure, the LLMs are unused."""
    return A2AAgent(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
    )


def _make_memory_poison_agent() -> MemoryPoisonAgent:
    return MemoryPoisonAgent(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
    )


def test_a2a_agent_is_applicable_when_is_multi_agent_true() -> None:
    """ASI07 (A2A) must run on an HttpAdapter target flagged multi-agent."""
    fp = _multi_agent_fingerprint()
    agent = _make_a2a_agent()
    assert agent.is_applicable(fp) is True


def test_memory_poison_agent_is_applicable_when_is_multi_agent_true() -> None:
    """ASI06 (memory poison) opens on multi-agent orchestrators even without
    declared memory — orchestration / supervisor state is fair game."""
    fp = _multi_agent_fingerprint()
    agent = _make_memory_poison_agent()
    assert agent.is_applicable(fp) is True


def test_a2a_agent_is_not_applicable_for_plain_http_target() -> None:
    """Sanity: ASI07 still stays off when neither framework nor multi-agent."""
    fp = TargetFingerprint(mode="http", ref="https://x.example/chat")
    agent = _make_a2a_agent()
    assert agent.is_applicable(fp) is False


# ---------------------------------------------------------------------------
# 3. Pure helper: name-shape detector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "transfer_to_agent",
        "transfer_to_booking_agent",
        "transfer_to_billing",
        "TRANSFER_TO_AGENT",  # case-insensitive
        "  transfer_to_agent  ",  # whitespace tolerant
        "agent_handoff",
        "route_to_agent",
        "delegate_to_agent",
        "handoff_to_agent",
        "handoff_to_supervisor",
    ],
)
def test_looks_like_multi_agent_tool_call_positive(name: str) -> None:
    assert _looks_like_multi_agent_tool_call(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "",
        "search",
        "kb_search",
        "lookup_contact",
        "open_ticket",
        "transfer_funds",  # NOT a sub-agent transfer; do not false-positive
        "agent_response",
        "route_request",
    ],
)
def test_looks_like_multi_agent_tool_call_negative(name: str) -> None:
    assert _looks_like_multi_agent_tool_call(name) is False
