"""Recon merges structured ``tool_calls`` from the HTTP adapter snapshot.

Pre-fix, recon only flipped ``has_tools_observed`` when the assistant text
included a substring like ``tool``/``search``/etc. (see the ``_TOOL_HINTS``
table). A target that responded with structured tool_call blocks but a
prose body like ``"Done."`` would slip past the substring matcher and the
swarm would treat it as "no tools observed" -- the tool-exfil + recon-
adaptive strategies then sat inert.

This test pins the fix: when the target's :attr:`HttpAdapter._last_response`
carries non-empty ``tool_calls``, ``has_tools_observed`` flips True AND the
tool names are OR-merged into ``declared_tools_observed`` regardless of the
prose body.
"""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.http import (
    HttpAdapter,
    HttpAdapterLastResponse,
    HttpAdapterToolCall,
)
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM


class _ProseOnlyToolHttpAdapter(HttpAdapter):
    """HttpAdapter that returns plain prose + structured tool_calls per call.

    The prose body contains NO substring matching the recon ``_TOOL_HINTS``
    table -- the only way ``has_tools_observed`` can flip is via the
    structured ``tool_calls`` snapshot.
    """

    def __init__(self) -> None:
        super().__init__("https://x.example", shape="openai", model="gpt-4o-mini")
        self._turn = 0
        self._fingerprint = TargetFingerprint(mode="http", ref="prose-only-tools")

    async def call(self, prompt: str, *, session: str | None = None) -> str:  # type: ignore[override]
        _ = prompt
        _ = session
        self._turn += 1
        self._last_response = HttpAdapterLastResponse(
            text="Done.",
            tool_calls=(
                HttpAdapterToolCall(name="kb_search", arguments={"q": "x"}),
                HttpAdapterToolCall(name="open_ticket", arguments={"id": 1}),
            ),
            raw=None,
        )
        return "Done."


async def test_recon_or_merges_structured_tool_calls_into_declared_tools(
    tmp_path: Any,
) -> None:
    adapter = _ProseOnlyToolHttpAdapter()
    # Pass-through StubLLM: the audit doesn't need a real LLM -- the deepen
    # loop will hit DONE on the very first response and exit cleanly.
    memory = SharedMemory("scan-recon-tools", root_dir=tmp_path)
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
    # Structured tool_calls drove has_tools=True even though the prose was
    # the substring-poor word "Done."
    assert fp.has_tools is True
    # ...and the tool names were OR-merged into declared_tools so downstream
    # strategies see the real surface.
    declared_lower = {n.lower() for n in fp.declared_tools}
    assert "kb_search" in declared_lower
    assert "open_ticket" in declared_lower


async def test_recon_tier1_structured_tool_survives_when_profile_omits_it(
    tmp_path: Any,
) -> None:
    """3-tier OR with Tier-1 wins: a structured tool_call name must survive into
    ``declared_tools`` even when the Tier-2 schema-extraction profile omits it.

    The profiler stub returns a profile naming only ``refund_payment``; the
    adapter fired a structured ``kb_search`` block. The final merge must keep
    BOTH — the Tier-2 list is canonical but the Tier-1 floor is OR-preserved.
    """
    import json

    profile_json = json.dumps(
        {
            "inferred_goal": "help customers",
            "domain": "support",
            "sensitive_actions": [],
            "declared_guardrails": [],
            "has_tools": True,
            "has_memory": False,
            "is_multi_agent": False,
            "external_systems": False,
            "cross_session_data": False,
            "declared_tools": ["refund_payment"],
            "confidence": 0.8,
        }
    )

    class _OneToolHttpAdapter(HttpAdapter):
        def __init__(self) -> None:
            super().__init__("https://x.example", shape="openai", model="gpt-4o-mini")
            self._fingerprint = TargetFingerprint(mode="http", ref="one-tool")

        async def call(self, prompt: str, *, session: str | None = None) -> str:  # type: ignore[override]
            _ = (prompt, session)
            self._last_response = HttpAdapterLastResponse(
                text="Done.",
                tool_calls=(HttpAdapterToolCall(name="kb_search", arguments={"q": "x"}),),
                raw=None,
            )
            return "Done."

    adapter = _OneToolHttpAdapter()
    memory = SharedMemory("scan-tier1-wins", root_dir=tmp_path)
    # The profiler extraction matches any prompt; declared_tools=["refund_payment"].
    agent = ReconAgent(attacker_llm=StubLLM(default=profile_json), model="stub", audit_rounds=0)
    try:
        await agent.run(adapter, memory)
    finally:
        await adapter.aclose()
    fp = memory.target_fingerprint()
    assert fp is not None
    declared_lower = {n.lower() for n in fp.declared_tools}
    # Tier-2 canonical name present...
    assert "refund_payment" in declared_lower
    # ...AND the Tier-1 structured tool the profile never saw is OR-preserved.
    assert "kb_search" in declared_lower


async def test_recon_audit_build_surfaces_deep_fields_and_coverage(
    tmp_path: Any,
) -> None:
    """The black-box audit fingerprint build threads the new evidence-grounded
    profile fields onto the fingerprint AND records the capability-audit
    coverage ledger + probe count.
    """
    import json

    profile_json = json.dumps(
        {
            "inferred_goal": "help customers",
            "domain": "support",
            "sensitive_actions": ["refund_payment"],
            "declared_guardrails": [],
            "has_tools": True,
            "has_memory": False,
            "is_multi_agent": False,
            "external_systems": False,
            "cross_session_data": False,
            "declared_tools": ["refund_payment"],
            "confidence": 0.8,
            "guardrail_posture": "weak",
            "requires_confirmation": False,
            "data_exposure": ["returns balances without verification"],
            "behavioral_flags": ["no refusals observed"],
            "touches_pii": True,
            "tool_descriptions": {"refund_payment": "issue a refund"},
        }
    )
    adapter = _ProseOnlyToolHttpAdapter()
    memory = SharedMemory("scan-deep-recon", root_dir=tmp_path)
    agent = ReconAgent(attacker_llm=StubLLM(default=profile_json), model="stub", audit_rounds=0)
    try:
        await agent.run(adapter, memory)
    finally:
        await adapter.aclose()
    fp = memory.target_fingerprint()
    assert fp is not None
    # Deep profile fields threaded onto the fingerprint.
    assert fp.guardrail_posture == "weak"
    assert fp.requires_confirmation is False
    assert fp.data_exposure == ["returns balances without verification"]
    # The profiler's flag plus the runtime time-channel recon-probe flag
    # (RECON-TC-001 now executes during the audit and surfaces an
    # inference-latency fingerprint).
    assert "no refusals observed" in fp.behavioral_flags
    assert any(f.startswith("inference-latency:") for f in fp.behavioral_flags)
    assert fp.touches_pii is True
    assert fp.tool_descriptions == {"refund_payment": "issue a refund"}
    # Coverage ledger + probe count came from the CapabilityAuditResult.
    assert isinstance(fp.recon_coverage, dict)
    assert fp.recon_coverage  # at least the seed-spine bands were marked
    assert fp.recon_probe_count > 0
