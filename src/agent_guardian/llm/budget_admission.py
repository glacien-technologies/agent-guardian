"""Pre-dispatch USD admission control for paid LLM calls."""

from __future__ import annotations

from collections.abc import Callable

from agent_guardian.core.budget import (
    BudgetExhausted,
    BudgetLedger,
    BudgetReceipt,
    tokens_to_usd,
)
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse
from agent_guardian.llm.usage_tracking import UsageTrackingLLM

__all__ = ["BudgetAdmissionLLM", "with_budget_admission"]


def _input_token_ceiling(request: LLMRequest) -> int:
    """Return a deliberately conservative token ceiling for request input."""
    return 32 + sum(
        len(message.content.encode("utf-8")) + len(message.role) + 32
        for message in request.messages
    )


class BudgetAdmissionLLM(BaseLLM):
    """Reserve a shared scan budget before forwarding an LLM request."""

    def __init__(
        self,
        inner: BaseLLM,
        *,
        ledger: BudgetLedger,
        agent_id: str,
        on_exhausted: Callable[[BudgetExhausted], None] | None = None,
    ) -> None:
        super().__init__(owns_client=False)
        self._inner = inner
        self._ledger = ledger
        self._agent_id = agent_id
        self._on_exhausted = on_exhausted
        self.provider = inner.provider

    async def complete(self, request: LLMRequest) -> LLMResponse:
        input_ceiling = _input_token_ceiling(request)
        output_ceiling = request.max_tokens
        receipt: BudgetReceipt
        try:
            receipt = self._ledger.reserve(
                self._agent_id,
                tokens=input_ceiling + output_ceiling,
                est_usd=tokens_to_usd(request.model, input_ceiling, output_ceiling),
            )
        except BudgetExhausted as exc:
            if self._on_exhausted is not None:
                self._on_exhausted(exc)
            raise

        try:
            response = await self._inner.complete(request)
        except BaseException:
            # The provider may have accepted a cancelled/failed request. With
            # no usage receipt, consume the reservation conservatively so a
            # later call cannot spend the same dollars a second time.
            self._ledger.commit(
                receipt,
                actual_usd=receipt.est_usd,
                actual_tokens=receipt.tokens,
            )
            raise

        self._ledger.commit(
            receipt,
            actual_usd=tokens_to_usd(
                request.model,
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
            ),
            actual_tokens=response.usage.total_tokens,
        )
        return response

    async def aclose(self) -> None:
        # Like UsageTrackingLLM, this decorator never owns the inner client.
        return None


def with_budget_admission(
    inner: BaseLLM,
    *,
    ledger: BudgetLedger,
    agent_id: str,
    on_exhausted: Callable[[BudgetExhausted], None] | None = None,
) -> BaseLLM:
    """Wrap ``inner`` without nesting two usage-accounting decorators."""
    if isinstance(inner, UsageTrackingLLM):
        admitted = BudgetAdmissionLLM(
            inner._inner,
            ledger=ledger,
            agent_id=agent_id,
            on_exhausted=on_exhausted,
        )
        return UsageTrackingLLM(admitted, counter=inner.counter)
    return BudgetAdmissionLLM(
        inner,
        ledger=ledger,
        agent_id=agent_id,
        on_exhausted=on_exhausted,
    )
