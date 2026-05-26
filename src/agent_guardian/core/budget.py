"""Budget controller (PRD §14.2).

A per-scan budget ceiling is split into per-agent slices. Slices may be
donated between agents under a single :class:`asyncio.Lock` so concurrent
agents cannot double-spend. All accounting is in token-equivalent integers.
"""

from __future__ import annotations

import asyncio

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["DEFAULT_SLICE_ALLOCATIONS", "BudgetController", "BudgetSlice"]


# Default per-agent allocations (PRD §14.2). Sum = 2,000,000.
DEFAULT_SLICE_ALLOCATIONS: dict[str, int] = {
    "recon": 50_000,
    "asi01": 150_000,
    "asi02": 150_000,
    "asi03": 150_000,
    "asi04": 150_000,
    "asi05": 150_000,
    "asi06": 150_000,
    "asi07": 150_000,
    "asi08": 150_000,
    "asi09": 150_000,
    "asi10": 150_000,
    "commander": 100_000,
    "evaluator": 350_000,
}


class BudgetSlice(BaseModel):
    """Per-agent budget envelope mutated as the scan progresses."""

    agent: str = Field(min_length=1)
    tokens_remaining: int = Field(ge=0)
    wall_seconds_remaining: float = Field(ge=0.0)

    # Slices mutate during a scan — frozen=False (default), but extras forbidden.
    model_config = ConfigDict(extra="forbid")


class BudgetController:
    """Thread-safe budget controller across asyncio tasks."""

    def __init__(
        self,
        total_tokens: int = 2_000_000,
        wall_seconds: float = 900.0,
        allocations: dict[str, int] | None = None,
    ) -> None:
        if total_tokens < 0:
            raise ValueError("total_tokens must be non-negative")
        if wall_seconds < 0:
            raise ValueError("wall_seconds must be non-negative")

        effective_allocations = (
            dict(allocations) if allocations is not None else dict(DEFAULT_SLICE_ALLOCATIONS)
        )
        allocated = sum(effective_allocations.values())
        if any(value < 0 for value in effective_allocations.values()):
            raise ValueError("Allocation values must be non-negative")
        if allocated > total_tokens:
            raise ValueError(
                f"Sum of allocations ({allocated}) exceeds total_tokens ({total_tokens})"
            )

        self._total_tokens = total_tokens
        self._wall_seconds = wall_seconds
        self._original_total = allocated
        self._lock = asyncio.Lock()
        self._slices: dict[str, BudgetSlice] = {}

        for agent, tokens in effective_allocations.items():
            share = tokens / allocated if allocated > 0 else 0.0
            self._slices[agent] = BudgetSlice(
                agent=agent,
                tokens_remaining=tokens,
                wall_seconds_remaining=wall_seconds * share,
            )

    def slice_for(self, agent: str) -> BudgetSlice:
        """Return the current slice for ``agent``.

        Raises:
            KeyError: if ``agent`` was not configured.
        """
        if agent not in self._slices:
            raise KeyError(f"No budget slice configured for agent {agent!r}")
        return self._slices[agent]

    def request(self, agent: str, tokens: int) -> bool:
        """Attempt to consume ``tokens`` from ``agent``'s slice.

        Returns ``True`` if the request succeeds; ``False`` if the slice is
        exhausted. Negative requests are rejected.
        """
        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        slice_ = self.slice_for(agent)
        if slice_.tokens_remaining < tokens:
            return False
        slice_.tokens_remaining -= tokens
        return True

    def donate(self, from_agent: str, to_agent: str, tokens: int) -> None:
        """Move ``tokens`` from one agent's slice to another's.

        Raises:
            ValueError: if ``tokens`` is negative or ``from_agent`` lacks
                the requested amount.
            KeyError: if either agent was not configured.
        """
        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        src = self.slice_for(from_agent)
        dst = self.slice_for(to_agent)
        if src.tokens_remaining < tokens:
            raise ValueError(
                f"Cannot donate {tokens} tokens from {from_agent!r}: only "
                f"{src.tokens_remaining} remaining"
            )
        src.tokens_remaining -= tokens
        dst.tokens_remaining += tokens

    def total_spent(self) -> int:
        """Total tokens consumed across all configured slices."""
        return self._original_total - self.total_remaining()

    def total_remaining(self) -> int:
        """Total tokens still available across all slices."""
        return sum(s.tokens_remaining for s in self._slices.values())
