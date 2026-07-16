"""Budget accounting for optional work performed after a scan completes."""

from __future__ import annotations

from agent_guardian.core.budget import tokens_to_usd
from agent_guardian.llm.usage_tracking import UsageCounter
from agent_guardian.models.scan import Scan

__all__ = ["can_run_probe_summaries", "fold_postscan_usage"]


def fold_postscan_usage(scan: Scan, counter: UsageCounter, model_spec: str) -> Scan:
    """Return a copy of ``scan`` with successful post-scan usage included."""
    extra_cost = tokens_to_usd(
        model_spec,
        counter.prompt_tokens,
        counter.completion_tokens,
    )
    cost_usd = scan.cost_usd + extra_cost
    budget = scan.budget
    if budget is not None:
        spent_usd = max(scan.cost_usd, budget.spent_usd) + extra_cost
        pct_of_cap = spent_usd / budget.cap_usd if budget.cap_usd else None
        budget = budget.model_copy(update={"spent_usd": spent_usd, "pct_of_cap": pct_of_cap})
    return scan.model_copy(
        update={
            "cost_usd": cost_usd,
            "tokens_total": scan.tokens_total + counter.total_tokens,
            "budget": budget,
        }
    )


def can_run_probe_summaries(
    cap_usd: float | None,
    spent_usd: float,
    reservation_usd: float,
) -> bool:
    """Return whether the conservative summary reservation fits the cap."""
    return cap_usd is None or reservation_usd <= max(0.0, cap_usd - spent_usd)
