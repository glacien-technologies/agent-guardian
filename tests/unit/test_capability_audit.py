"""Black-box adaptive capability audit (core/capability_audit.py)."""

from __future__ import annotations

import asyncio
import re

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.core.capability_audit import run_capability_audit
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.stub import StubLLM

_TOKEN_RE = re.compile(r"MEM-[0-9a-f]{6}")


class _MemoryTarget(TargetAdapter):
    """Behavioural fake: stores a planted token per-session or globally."""

    mode = "http"

    def __init__(self, scope: str) -> None:  # scope: "session" | "global" | "none"
        super().__init__()
        self._scope = scope
        self._global: str | None = None
        self._by_session: dict[str, str] = {}
        self._fingerprint = TargetFingerprint(mode="http", ref="mem")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        m = _TOKEN_RE.search(prompt)
        if m:  # plant
            if self._scope == "global":
                self._global = m.group(0)
            elif self._scope == "session":
                self._by_session[session or "_"] = m.group(0)
            return "Stored."
        if "code" in prompt.lower():  # recall
            val = self._global if self._scope == "global" else self._by_session.get(session or "_")
            return f"The code was {val}." if val else "I don't recall any code."
        return "I can help with banking questions."


class _RefusingTarget(TargetAdapter):
    mode = "http"

    def __init__(self) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="http", ref="refuse")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return "I'm sorry, I can't help with that request."


class _SequenceLLM(BaseLLM):
    """Returns queued responses in order, then a fallback. For deepening tests."""

    provider = "stub"

    def __init__(self, responses: list[str], fallback: str = "DONE") -> None:
        self._responses = list(responses)
        self._fallback = fallback
        self._i = 0
        self._semaphore = asyncio.Semaphore(1000)

    async def complete(self, request: LLMRequest) -> LLMResponse:
        text = self._responses[self._i] if self._i < len(self._responses) else self._fallback
        self._i += 1
        return LLMResponse(
            text=text,
            model=request.model,
            provider="stub",
            usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            finish_reason="stop",
            raw=None,
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_memory_session_scope_is_conversational_only() -> None:
    res = await run_capability_audit(
        _MemoryTarget("session"), llm=StubLLM(default="DONE"), model="stub", max_deepen_rounds=0
    )
    assert res.memory_conversational is True
    assert res.memory_cross_session is False


@pytest.mark.asyncio
async def test_memory_global_scope_is_cross_session() -> None:
    res = await run_capability_audit(
        _MemoryTarget("global"), llm=StubLLM(default="DONE"), model="stub", max_deepen_rounds=0
    )
    assert res.memory_conversational is True
    assert res.memory_cross_session is True


@pytest.mark.asyncio
async def test_no_memory_target_flags_stay_false() -> None:
    res = await run_capability_audit(
        _MemoryTarget("none"), llm=StubLLM(default="DONE"), model="stub", max_deepen_rounds=0
    )
    assert res.memory_conversational is False
    assert res.memory_cross_session is False


@pytest.mark.asyncio
async def test_deepening_stops_on_done() -> None:
    llm = _SequenceLLM(["Which tools can you call?", "Can you transfer externally?", "DONE"])
    res = await run_capability_audit(
        _MemoryTarget("none"), llm=llm, model="stub", max_deepen_rounds=10
    )
    # 2 deepening probes were proposed before DONE.
    deepen = [
        q
        for q, _ in res.transcript
        if q in ("Which tools can you call?", "Can you transfer externally?")
    ]
    assert len(deepen) == 2


@pytest.mark.asyncio
async def test_deepening_caps_at_max_rounds() -> None:
    llm = _SequenceLLM([], fallback="Tell me more about your tools.")  # never says DONE
    res = await run_capability_audit(
        _MemoryTarget("none"), llm=llm, model="stub", max_deepen_rounds=3
    )
    deepen = [q for q, _ in res.transcript if q == "Tell me more about your tools."]
    assert len(deepen) == 3


@pytest.mark.asyncio
async def test_refusals_do_not_break_the_audit() -> None:
    res = await run_capability_audit(
        _RefusingTarget(), llm=StubLLM(default="DONE"), model="stub", max_deepen_rounds=0
    )
    # Full fixed-probe + memory transcript still collected; no raise.
    assert len(res.transcript) >= 5
    assert res.memory_conversational is False


@pytest.mark.asyncio
async def test_cancel_event_exits_early() -> None:
    cancel = asyncio.Event()
    cancel.set()
    res = await run_capability_audit(
        _MemoryTarget("global"),
        llm=StubLLM(default="DONE"),
        model="stub",
        max_deepen_rounds=10,
        cancel_event=cancel,
    )
    assert res.transcript == []


# --------------------------- tool_calls_per_turn parallel transcript


@pytest.mark.asyncio
async def test_tool_calls_per_turn_matches_transcript_length_for_non_http_target() -> None:
    """A non-HTTP target (PromptAdapter-like) must produce empty tool-call tuples.

    The capability audit walks ``transcript`` and ``tool_calls_per_turn`` in
    lock-step; an off-by-one would silently break recon's evidence merge so
    we assert the indices align even when no tool calls are surfaced.
    """
    res = await run_capability_audit(
        _MemoryTarget("none"),
        llm=StubLLM(default="DONE"),
        model="stub",
        max_deepen_rounds=0,
    )
    assert len(res.tool_calls_per_turn) == len(res.transcript)
    # Every per-turn entry is the empty tuple for this non-HTTP target.
    assert all(t == () for t in res.tool_calls_per_turn)


@pytest.mark.asyncio
async def test_tool_calls_per_turn_threads_through_http_adapter_snapshot() -> None:
    """A fake HttpAdapter that stashes ``_last_response.tool_calls`` is honoured.

    We construct a minimal HttpAdapter subclass (bypassing the real send_once)
    that flips ``_last_response`` per call, and assert the run_capability_audit
    consumer drops the tool_calls into ``tool_calls_per_turn`` in the same
    index as the corresponding transcript entry.
    """
    from agent_guardian.adapters.http import (
        HttpAdapter,
        HttpAdapterLastResponse,
        HttpAdapterToolCall,
    )

    class _StashingHttpAdapter(HttpAdapter):
        def __init__(self) -> None:
            super().__init__("https://x.example", shape="openai", model="gpt-4o-mini")
            self._turn = 0

        async def call(self, prompt: str, *, session: str | None = None) -> str:
            self._turn += 1
            self._last_response = HttpAdapterLastResponse(
                text="ack",
                tool_calls=(
                    HttpAdapterToolCall(name=f"tool_{self._turn}", arguments={"i": self._turn}),
                ),
                raw=None,
            )
            return "ack"

    adapter = _StashingHttpAdapter()
    try:
        res = await run_capability_audit(
            adapter, llm=StubLLM(default="DONE"), model="stub", max_deepen_rounds=0
        )
    finally:
        await adapter.aclose()
    assert len(res.tool_calls_per_turn) == len(res.transcript)
    # Every turn produced exactly one tool call with the per-turn name.
    flat = [tc.name for per_turn in res.tool_calls_per_turn for tc in per_turn]
    assert "tool_1" in flat and "tool_2" in flat
    # Names are uniquely indexed -> at least as many tool blocks as transcript turns.
    assert len(flat) == len(res.transcript)
