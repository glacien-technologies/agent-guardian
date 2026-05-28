"""PoV script + success-indicator model (M2 Pattern 2).

A :class:`PoVScript` is a deterministic reproducer: an ordered list of setup
messages, an ordered list of trigger messages, and a :class:`SuccessIndicator`
that decides — from the observed transport responses — whether the attack
succeeded. The script carries a ``seed`` so any stochastic choice in replay is
reproducible.

Indicators are deliberately observable and low-false-positive:

* ``contains`` / ``exact`` / ``regex`` — string predicates over the response
  (e.g. a customer-seeded canary string for the secret-extraction agent).
* ``semantic`` — an LLM judge verdict, for cases where the win is not a literal
  string match. Requires a judge callable injected at run time.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum

__all__ = ["IndicatorKind", "PoVScript", "SuccessIndicator"]


class IndicatorKind(str, Enum):
    CONTAINS = "contains"
    EXACT = "exact"
    REGEX = "regex"
    SEMANTIC = "semantic"


# A semantic judge takes (observation, criteria) and returns True iff the
# observation satisfies the criteria. Injected at run time so the harness has
# no hard LLM dependency.
SemanticJudge = Callable[[str, str], Awaitable[bool]]


@dataclass(frozen=True)
class SuccessIndicator:
    """Decides whether an observation proves the vulnerability fired."""

    kind: IndicatorKind
    value: str
    case_sensitive: bool = False

    async def matches(self, observation: str, *, judge: SemanticJudge | None = None) -> bool:
        if self.kind is IndicatorKind.CONTAINS:
            hay = observation if self.case_sensitive else observation.lower()
            needle = self.value if self.case_sensitive else self.value.lower()
            return needle in hay
        if self.kind is IndicatorKind.EXACT:
            a, b = (observation, self.value)
            if not self.case_sensitive:
                a, b = a.lower(), b.lower()
            return a.strip() == b.strip()
        if self.kind is IndicatorKind.REGEX:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return re.search(self.value, observation, flags) is not None
        if self.kind is IndicatorKind.SEMANTIC:
            if judge is None:
                raise ValueError("semantic indicator requires a judge callable")
            return await judge(observation, self.value)
        raise ValueError(f"unknown indicator kind {self.kind!r}")  # pragma: no cover


@dataclass(frozen=True)
class PoVScript:
    """A reproducible attack reproducer."""

    scenario_id: str
    indicator: SuccessIndicator
    setup: list[str] = field(default_factory=list)
    trigger: list[str] = field(default_factory=list)
    seed: int = 0
    determinism_notes: str = ""

    def all_messages(self) -> list[str]:
        return [*self.setup, *self.trigger]
