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
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    calls: int = 0

    def add_response(self, response: LLMResponse) -> None:
        """Fold one :class:`LLMResponse`'s usage into the counter."""
        usage = response.usage
        self.prompt_tokens += int(usage.prompt_tokens)
        self.completion_tokens += int(usage.completion_tokens)
        self.total_tokens += int(usage.total_tokens)
        self.calls += 1

    def merge(self, other: UsageCounter) -> None:
        """Fold another counter's totals into this one. Useful for aggregation."""
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens
        self.calls += other.calls

    def snapshot(self) -> dict[str, int]:
        """Return a plain-dict snapshot for serialisation into reports."""
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "calls": self.calls,
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
        # Intentionally skip ``super().__init__`` — we own no httpx client,
        # no semaphore, no api_key. All transport happens via ``inner``.
        self._inner = inner
        self.counter = counter if counter is not None else UsageCounter()
        self._lock = asyncio.Lock()
        # Mirror the inner provider so downstream code doesn't need to peek.
        self.provider = inner.provider
        # The wrapper itself owns no client.
        self._owns_client = False

    async def complete(self, request: LLMRequest) -> LLMResponse:
        response = await self._inner.complete(request)
        async with self._lock:
            self.counter.add_response(response)
        return response

    async def aclose(self) -> None:
        # The wrapper never owns the inner client. Closing is the caller's job.
        return None
