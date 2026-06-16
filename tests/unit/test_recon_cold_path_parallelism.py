"""Recon cold-path parallelism invariants (rc37 deep-review HIGH-1; for #206).

The rc37 deep-review found that PR #238's recon-cap floor recovered only
11/27 fast scans because ``run_capability_audit`` (followed by recon's
post-audit transcript loop) serializes target round-trips that have no causal
dependency on each other. This file pins the invariants the fix must satisfy:

1. The Purpose / Tools / Multi-agent seed probes have no inter-probe data
   dependency — the audit MUST issue them concurrently so wall time is bounded
   by ``max(latency)`` rather than ``sum(latencies)``.
2. The recon agent's post-audit ``_extract_tool_names`` LLM calls are
   independent per transcript turn — the agent MUST fan them out concurrently
   rather than awaiting one extraction per turn in sequence.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.core.capability_audit import run_capability_audit
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage


class _ConcurrencyTrackingTarget(TargetAdapter):
    """Records the maximum number of in-flight ``call`` invocations.

    Each ``call`` sleeps for ``per_call_seconds`` so concurrent calls actually
    overlap on the event loop. ``max_concurrent`` is the high-water mark of
    simultaneously in-flight calls — the invariant the parallelism fix
    must lift above 1.
    """

    mode = "http"

    def __init__(self, *, per_call_seconds: float = 0.1) -> None:
        super().__init__()
        self._per_call_seconds = per_call_seconds
        self._fingerprint = TargetFingerprint(mode="http", ref="concurrency-tracker")
        self.in_flight = 0
        self.max_concurrent = 0
        self.calls: list[str] = []
        self._lock = asyncio.Lock()

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        async with self._lock:
            self.in_flight += 1
            if self.in_flight > self.max_concurrent:
                self.max_concurrent = self.in_flight
            self.calls.append(prompt)
        try:
            await asyncio.sleep(self._per_call_seconds)
        finally:
            async with self._lock:
                self.in_flight -= 1
        # A benign banking-domain reply so coverage marks PARTIAL/CONFIRMED but
        # nothing in the audit treats it as an error.
        return (
            "I'm a banking assistant — I can help you look up account balances "
            "and transaction history."
        )


class _NullLLM(BaseLLM):
    """LLM that returns an empty proposal so the deepen loop stops fast.

    Used to keep the audit short — this test exercises the SEED-phase
    parallelism invariant, not the deepening loop.
    """

    provider = "stub"

    def __init__(self) -> None:
        super().__init__(owns_client=False)

    async def complete(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            text="",
            model=request.model,
            provider="stub",
            usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            finish_reason="stop",
            raw=None,
        )

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_seed_probes_issued_concurrently() -> None:
    """P/T/A seed probes must overlap in flight, not run strictly sequentially.

    rc37 deep-review HIGH-1: the 74s cold-path before the first
    ``tool_extraction`` is dominated by independent target round-trips
    awaited one at a time. The seed prompts have no causal dependency on
    each other — they MUST be issued concurrently.
    """
    target = _ConcurrencyTrackingTarget(per_call_seconds=0.1)
    result = await run_capability_audit(
        target,
        llm=_NullLLM(),
        model="stub",
        max_deepen_rounds=0,
    )
    # The audit ran (transcript populated).
    assert len(result.transcript) >= 3
    # Invariant: at least two seed probes were in flight at the same time.
    # Sequential awaits cap this at 1; concurrent gather lifts it to >=2.
    assert target.max_concurrent >= 2, (
        f"expected seed probes to overlap in flight; "
        f"max_concurrent={target.max_concurrent}, calls={len(target.calls)}"
    )


class _SlowExtractionLLM(BaseLLM):
    """LLM whose ``complete`` sleeps so concurrent calls show as overlap.

    Tracks max in-flight ``complete`` calls so the test can assert the
    post-audit ``_extract_tool_names`` calls fan out instead of awaiting one
    at a time.
    """

    provider = "stub"

    def __init__(self, *, per_call_seconds: float = 0.05) -> None:
        super().__init__(owns_client=False)
        self._per_call_seconds = per_call_seconds
        self.in_flight = 0
        self.max_concurrent = 0
        self._lock = asyncio.Lock()

    async def complete(self, request: LLMRequest) -> LLMResponse:
        async with self._lock:
            self.in_flight += 1
            if self.in_flight > self.max_concurrent:
                self.max_concurrent = self.in_flight
        try:
            await asyncio.sleep(self._per_call_seconds)
        finally:
            async with self._lock:
                self.in_flight -= 1
        return LLMResponse(
            text="[]",
            model=request.model,
            provider="stub",
            usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            finish_reason="stop",
            raw=None,
        )

    async def aclose(self) -> None:
        return None


class _StaticReplyTarget(TargetAdapter):
    """Target that returns the same prose reply for every probe.

    Used by the post-audit tool_extraction test so the recon agent builds a
    multi-turn transcript and then must extract tool names from each turn.
    """

    mode = "http"

    def __init__(self) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="http", ref="static-reply")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return (
            "I'm a banking assistant. I can look up your balance, transfer money, "
            "and use my knowledge base to answer policy questions."
        )


@pytest.mark.asyncio
async def test_post_audit_tool_extraction_fans_out() -> None:
    """Per-turn ``_extract_tool_names`` calls must run concurrently.

    rc37 deep-review HIGH-1: the recon agent's post-audit loop iterates the
    transcript and awaits one LLM extraction per turn. Each turn's extraction
    is read-only on the LLM and shares no input with other turns — the agent
    MUST fan them out so the cold-path scales with one round-trip, not N.
    """
    target = _StaticReplyTarget()
    llm = _SlowExtractionLLM(per_call_seconds=0.05)
    agent = ReconAgent(
        attacker_llm=llm,
        model="stub",
        budget=AgentBudget(),
        audit_rounds=0,
    )
    memory = SharedMemory(scan_id="test-recon-cold-path")
    await agent.run(target, memory)
    # The audit produced at least three transcript turns (P/T/A seeds + memory
    # probes). For each non-error reply the agent invokes one ``_extract_tool_names``
    # LLM call; the SEED phase issues a couple more LLM calls so the high-water
    # mark counts both. The invariant is that more than one extraction is in
    # flight at once.
    assert llm.max_concurrent >= 2, (
        f"expected post-audit extractions to overlap; max_concurrent={llm.max_concurrent}"
    )
