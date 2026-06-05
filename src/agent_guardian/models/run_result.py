"""Per-run (per-agent) aggregated verdict — strongest-evidence rollup.

A single agent runs many turns; the *run* verdict is the strongest-evidence
turn, not the first/last/average. This model carries that rollup so the
dashboard and reports can show "this category resolved as EXPLOITED, proven by
turn 6 @ 0.95" rather than a noisy per-turn stream.

Computed by :func:`agent_guardian.core.run_aggregator.aggregate_run_verdicts`
and attached to :class:`~agent_guardian.agents.base.AgentReport`.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["AsiRunResult"]


class AsiRunResult(BaseModel):
    """Strongest-evidence rollup of one agent's per-turn verdicts."""

    run_verdict: str
    run_confidence: float = Field(ge=0.0, le=1.0)
    best_evidence_turn: int
    evaluator_attack_detected: bool = False
    confirmed_exploited: bool = False

    model_config = ConfigDict(extra="ignore")
