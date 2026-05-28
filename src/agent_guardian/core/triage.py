"""Two-tier finding triage (M2 Pattern 3).

A cheap classifier scores every candidate finding (~$0.001/finding); only the
top ``top_k_pct`` (default 20%) — or whatever fits ``budget_cap_usd`` — go to
the expensive agentic deep analyst (~$0.50/finding). Theori RoboDuck's published
ratio.

The cheap classifier prefers a single-token log-prob signal when the LLM client
exposes one; otherwise it falls back to a scored judge call. Either way the
output is a 0-1 score used purely for *ordering* — the PoV oracle (Pattern 2)
and the critic (Pattern 6) make the real accept/reject decision downstream.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

__all__ = ["AnalyzedFinding", "RawFinding", "TwoTierTriage"]

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class RawFinding:
    """A specialist-emitted finding candidate, pre-triage."""

    finding_id: str
    summary: str
    asi: str
    severity: str = "medium"
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalyzedFinding:
    """A finding enriched by the cheap score + (optionally) the deep analyst."""

    raw: RawFinding
    cheap_score: float
    deep_analyzed: bool
    confidence: float
    notes: str = ""


# A scorer maps a RawFinding to a 0-1 likelihood. Injected so the triage has no
# hard LLM dependency (tests pass a deterministic scorer; production wires a
# log-prob/judge-backed one).
CheapScorer = Callable[[RawFinding], Awaitable[float]]
# A deep analyst maps a RawFinding to (confidence, notes).
DeepAnalyst = Callable[[RawFinding], Awaitable[tuple[float, str]]]


class TwoTierTriage:
    """Cheap-score everything, deep-analyze only the top slice within budget."""

    def __init__(
        self,
        *,
        cheap_scorer: CheapScorer,
        deep_analyst: DeepAnalyst,
        deep_cost_usd: float = 0.50,
    ) -> None:
        self._cheap = cheap_scorer
        self._deep = deep_analyst
        self._deep_cost = deep_cost_usd

    async def run(
        self,
        findings: list[RawFinding],
        *,
        top_k_pct: float = 0.20,
        budget_cap_usd: float | None = None,
    ) -> list[AnalyzedFinding]:
        if not findings:
            return []
        if not 0.0 < top_k_pct <= 1.0:
            raise ValueError("top_k_pct must be in (0, 1]")

        scored = [(f, await self._cheap(f)) for f in findings]
        scored.sort(key=lambda pair: pair[1], reverse=True)

        # How many can we afford to deep-analyze?
        by_pct = max(1, round(len(scored) * top_k_pct))
        if budget_cap_usd is not None and self._deep_cost > 0:
            by_budget = int(budget_cap_usd // self._deep_cost)
            deep_n = min(by_pct, by_budget)
        else:
            deep_n = by_pct
        _LOG.info(
            "triage: %d candidates, deep-analyzing top %d (top_k_pct=%.2f, budget_cap=%s)",
            len(scored),
            deep_n,
            top_k_pct,
            budget_cap_usd,
        )

        out: list[AnalyzedFinding] = []
        for i, (finding, score) in enumerate(scored):
            if i < deep_n:
                confidence, notes = await self._deep(finding)
                out.append(AnalyzedFinding(finding, score, True, confidence, notes))
            else:
                # Not deep-analyzed — carry the cheap score as the confidence.
                out.append(AnalyzedFinding(finding, score, False, score, "cheap-pass only"))
        return out
