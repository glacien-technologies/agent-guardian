"""Integration tests for :class:`ReconAgent` (recon redesign).

Recon now produces a structured intent+surface profile from the richest evidence
available: white-box (read the system prompt / source) when possible, else a
black-box adaptive capability audit. These tests exercise the end-to-end
``ReconAgent.run`` integration; the unit-level profiler and audit mechanics live
in ``test_profiler.py`` / ``test_capability_audit.py``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.recon import ReconAgent
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

_TOKEN_RE = re.compile(r"MEM-[0-9a-f]{6}")


class _BlackBoxMemoryTarget(TargetAdapter):
    """Black-box endpoint with global (cross-session) memory of a planted token."""

    mode = "http"

    def __init__(self) -> None:
        super().__init__()
        self._token: str | None = None
        self._fingerprint = TargetFingerprint(mode="http", ref="bb-mem")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        m = _TOKEN_RE.search(prompt)
        if m:
            self._token = m.group(0)
            return "Stored."
        if "code" in prompt.lower():
            return f"The code was {self._token}." if self._token else "I don't recall a code."
        return "I help Acme Bank customers with refunds and balance checks."


# ----------------------------------------------------------------- white-box


async def test_recon_white_box_prompt_extracts_profile(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    target = make_target(
        llm=StubLLM(default="ok"),
        prompt="You are FinBot, a banking refund assistant with get_balance and refund_payment.",
    )
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default=_PROFILE_JSON), model="stub")
    report = await agent.run(target, memory)
    assert report.terminated_by == "success"
    fp = memory.target_fingerprint()
    assert fp is not None
    assert fp.profile_source == "prompt"
    assert fp.inferred_goal == "authorize refunds for verified customers"
    assert fp.has_tools is True
    assert "refund_payment" in fp.declared_tools


async def test_recon_white_box_extraction_failure_falls_back_without_crashing(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    # Attacker returns junk -> profile_from_material yields nothing -> recon
    # falls back to the black-box audit against the prompt target; the target's
    # replies advertise tools, so the heuristic still flips has_tools.
    target = make_target(llm=StubLLM(default="I have access to file_read and web_search tools."))
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default="not json"), model="stub", audit_rounds=0)
    report = await agent.run(target, memory)
    fp = memory.target_fingerprint()
    assert fp is not None  # recon never crashes
    assert report.terminated_by == "success"
    assert fp.has_tools is True


# ----------------------------------------------------------------- black-box


async def test_recon_black_box_detects_cross_session_memory(
    make_memory: Callable[..., SharedMemory],
) -> None:
    target = _BlackBoxMemoryTarget()
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default=_PROFILE_JSON), model="stub", audit_rounds=0)
    await agent.run(target, memory)
    fp = memory.target_fingerprint()
    assert fp is not None
    assert fp.profile_source == "endpoint"
    assert fp.has_memory is True  # planted token recalled in-session
    assert fp.cross_session_data_detected is True  # ...and in a fresh session


async def test_recon_black_box_writes_forensic_reflections(
    make_memory: Callable[..., SharedMemory],
) -> None:
    target = _BlackBoxMemoryTarget()
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default=_PROFILE_JSON), model="stub", audit_rounds=0)
    await agent.run(target, memory)
    reflections = memory.reflections_for("recon-agent")
    assert reflections, "audit must persist a forensic reflection per turn"
    parsed = [json.loads(c) for c in reflections]
    assert all(r["event"] == "recon_audit" for r in parsed)
    assert all(r["prompt"] and r["target_response"] for r in parsed)


# ----------------------------------------------------------------- preservation


async def test_recon_carries_existing_fingerprint_signal_forward(
    make_memory: Callable[..., SharedMemory],
    make_target: Callable[..., PromptAdapter],
) -> None:
    """A statically-declared surface signal must not regress through recon."""
    declared = TargetFingerprint(
        mode="framework",
        ref="<pre-existing>",
        has_tools=True,
        has_memory=False,
        is_multi_agent=True,
        notes="pre-existing static description",
    )
    target = make_target(llm=StubLLM(default="plain"), fingerprint=declared)
    memory = make_memory()
    agent = ReconAgent(attacker_llm=StubLLM(default="not json"), model="stub", audit_rounds=0)
    await agent.run(target, memory)
    fp = memory.target_fingerprint()
    assert fp is not None
    assert fp.has_tools is True  # preserved
    assert fp.is_multi_agent is True
    assert fp.mode == "framework"
