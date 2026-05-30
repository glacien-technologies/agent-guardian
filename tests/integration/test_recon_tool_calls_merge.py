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
