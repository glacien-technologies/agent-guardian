"""Parallel-model racing (M2 Pattern 4).

For high-value probes, fire the same task at several models concurrently and
take the first response that passes the validator (the PoV oracle from
Pattern 2); cancel the losers. No LiteLLM — the panel is a list of our own
``llm/`` provider clients behind a thin endpoint wrapper.

Cancelled siblings still report their token usage so the budget ledger
(Pattern 7) charges every call that was actually issued.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from agent_guardian.core.race import race_first_success
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse

__all__ = ["ModelEndpoint", "ModelRacer", "RaceResult"]


@dataclass(frozen=True)
class ModelEndpoint:
    """One model in the race panel — a client + the model name to request."""

    llm: BaseLLM
    model: str

    @property
    def label(self) -> str:
        return f"{self.llm.provider}:{self.model}"


@dataclass(frozen=True)
class RaceResult:
    """Outcome of a model race."""

    winner_label: str | None
    response: LLMResponse | None
    panel_size: int
    cancelled: int
    errors: int


class ModelRacer:
    """First-valid-success across a panel of model endpoints."""

    async def race(
        self,
        request: LLMRequest,
        panel: list[ModelEndpoint],
        *,
        validator: Callable[[LLMResponse], Awaitable[bool] | bool],
    ) -> RaceResult:
        if not panel:
            raise ValueError("model race needs a non-empty panel")

        factories: dict[str, Callable[[], Awaitable[LLMResponse]]] = {}
        for ep in panel:
            # Bind ``ep`` per-iteration so each factory targets its own model.
            def _make(endpoint: ModelEndpoint) -> Callable[[], Awaitable[LLMResponse]]:
                req = request.model_copy(update={"model": endpoint.model})

                async def _call() -> LLMResponse:
                    return await endpoint.llm.complete(req)

                return _call

            factories[ep.label] = _make(ep)

        outcome = await race_first_success(factories, validator)
        return RaceResult(
            winner_label=outcome.winner_label,
            response=outcome.winner,
            panel_size=len(panel),
            cancelled=outcome.cancelled,
            errors=outcome.errors,
        )
