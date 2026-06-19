"""Cumulative usage accounting wrapper around :class:`BaseLLM`.

Real cost tracking requires a faithful count of how many tokens the
attacker / evaluator / commander LLMs actually consumed during a scan,
across many calls and many concurrent agents. We can't reach into each
provider client to instrument it (we don't own all of them), and we
don't want to plumb a tracker through every call site by hand.

:class:`UsageTrackingLLM` solves that with the decorator pattern: wrap
any :class:`BaseLLM` and it transparently forwards :meth:`complete`
while accumulating the per-response :class:`~agent_guardian.llm.base.LLMUsage`
into a thread-safe counter. The wrapper preserves provider identity so
downstream code (cost lookup, error handling) doesn't need to special-case
it.

Concurrency: the counter uses :class:`asyncio.Lock` so simultaneous
:meth:`complete` calls from a TaskGroup don't lose counts on read-modify-
write of the running totals.

Cost note: tokens times the per-model rate is computed elsewhere (see
:mod:`agent_guardian.cost`). This module records the raw counts only —
keeping the pricing concern out of the LLM transport layer.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse

__all__ = ["UsageCounter", "UsageTrackingLLM"]


@dataclass
class UsageCounter:
    """Cumulative token counts across many :class:`LLMResponse` returns.

    ``calls`` is the number of completion round-trips successfully observed.
    A call that raised before returning a response is not counted.

    ``unseeded_llm_calls`` (#231 point 5) is the number of completion calls
    dispatched with ``request.seed is None``. It is a self-diagnosing signal:
    when a scan was launched with ``--seed`` but some path forgot to thread the
    seed onto its :class:`LLMRequest`, this counter is non-zero. It is recorded
    unconditionally at dispatch; the report only surfaces it under ``coverage``
    when the scan itself was seeded (an unseeded scan trivially has every call
    unseeded, which is not a defect).
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    calls: int = 0
    unseeded_llm_calls: int = 0

    def add_response(self, response: LLMResponse) -> None:
        """Fold one :class:`LLMResponse`'s usage into the counter."""
        usage = response.usage
        self.prompt_tokens += int(usage.prompt_tokens)
        self.completion_tokens += int(usage.completion_tokens)
        self.total_tokens += int(usage.total_tokens)
        self.calls += 1

    def note_request(self, request: LLMRequest) -> None:
        """Record dispatch-side signals for ``request`` (#231 point 5).

        Counts the call as unseeded when it carries no seed so a seeded scan
        can self-diagnose a seed-threading miss.
        """
        if request.seed is None:
            self.unseeded_llm_calls += 1

    def merge(self, other: UsageCounter) -> None:
        """Fold another counter's totals into this one. Useful for aggregation."""
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens
        self.calls += other.calls
        self.unseeded_llm_calls += other.unseeded_llm_calls

    def snapshot(self) -> dict[str, int]:
        """Return a plain-dict snapshot for serialisation into reports."""
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "calls": self.calls,
            "unseeded_llm_calls": self.unseeded_llm_calls,
        }


class UsageTrackingLLM(BaseLLM):
    """Decorator that mirrors :class:`BaseLLM` while accumulating usage.

    The wrapper forwards every call to the wrapped client and folds the
    returned :class:`LLMUsage` into :attr:`counter`. The wrapper's
    ``provider`` attribute mirrors the inner client so price-table lookups
    and other provider-keyed logic see the underlying provider.

    Lifecycle: :meth:`aclose` is a no-op on the wrapper — the caller owns
    the wrapped client. Wrapping is purely additive.
    """

    def __init__(self, inner: BaseLLM, *, counter: UsageCounter | None = None) -> None:
        # Pass ``owns_client=False`` so BaseLLM skips httpx setup; transport
        # happens via ``inner``. The base initialiser still wires up the
        # semaphore and other plumbing so isinstance(self, BaseLLM) holds.
        super().__init__(owns_client=False)
        self._inner = inner
        self.counter = counter if counter is not None else UsageCounter()
        self._lock = asyncio.Lock()
        # Mirror the inner provider so downstream code doesn't need to peek.
        self.provider = inner.provider

    async def complete(self, request: LLMRequest) -> LLMResponse:
        # Record the dispatch-side seed signal (#231 point 5) before the call
        # so an unseeded request is counted even if the provider raises.
        async with self._lock:
            self.counter.note_request(request)
        response = await self._inner.complete(request)
        async with self._lock:
            self.counter.add_response(response)
        return response

    async def aclose(self) -> None:
        # The wrapper never owns the inner client. Closing is the caller's job.
        return None
