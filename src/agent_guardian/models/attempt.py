"""Attempt model — one per-turn attack execution that produced a verdict.

A :class:`Finding` aggregates over an attack-vulnerability pair
``(probe_id, asi)``. Each individual turn that landed a verdict-qualifying
result against that vulnerability becomes an :class:`Attempt` under the
aggregated Finding. The Finding's ``confidence`` is the Wilson lower bound of
``success_count / len(attempts)`` — a numeric reproducibility signal computed
*after* the judge speaks (the judge stays an LLM over the third-party agent's
full response; Wilson is the universal framework signal layered on top).

The per-attempt legacy id, prompt, response, evidence span, and judge
confidence are preserved verbatim so the audit trail and the dashboard's
per-attempt drill view stay resolvable. See
``docs/_design/finding-aggregation-redesign-2026-06.md`` §II.B for the locked
spec.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["Attempt"]


class Attempt(BaseModel):
    """Single attack execution attempt (turn) that produced a verdict.

    When a probe lands successfully on multiple turns, each turn becomes
    an :class:`Attempt` under the aggregated :class:`Finding`. The
    Finding's confidence is then ``Wilson(success_count / len(attempts))``.
    """

    # Unique identifier for THIS turn's finding record (legacy per-turn id).
    # Preserved from the original Finding.id so the audit trail and any
    # ``transcript_ref`` strings already on disk remain resolvable.
    id: str = Field(min_length=1)

    # Source probe id this attempt fired against. May be the parent probe id
    # OR a mutant probe id (``<parent>-mutant-<op>``) — the aggregator
    # collapses mutants to the parent before bucketing.
    probe_id: str = Field(min_length=1)

    # ASI category the attempt belongs to (string value, e.g. ``"ASI03"``).
    # Stored as the enum string value (not the enum itself) so the model
    # stays a leaf with no enum import cycle and so on-disk JSON is the
    # canonical representation.
    asi: str = Field(min_length=1)

    # 1, 2, 3, ... — matches the old per-turn ``attempt_count`` (the turn
    # number this attempt rode on).
    sequence: int = Field(ge=1)

    # Judge's verdict on THIS attempt (six-verdict v2 taxonomy).
    verdict_v2: str

    # Judge's confidence that this specific verdict is correct.
    confidence: float = Field(ge=0.0, le=1.0)

    # ``verdict_to_success(verdict_v2)`` — True for exploited (and the
    # legacy ``fail`` projection).
    success: bool

    # The (capped) target reply that proves this attempt's compromise.
    trigger_response: str | None = None
    # The exact attacker prompt that produced this attempt.
    trigger_prompt: str | None = None
    # Structured corroboration tags (``observable``, ``tool_call:<name>``, ...).
    evidence_types: list[str] = Field(default_factory=list)
    # The judge's verbatim quoted span that justified the verdict. Empty
    # when the judge surfaced no quotable span.
    evidence_quote: str = ""
    created_at: datetime

    # Per-attempt repeat-trial consistency, if measured (FULL mode only):
    # ``"<reproduced>/<n>"`` (e.g. ``"3/3"``).
    reproduced_n_of_m: str | None = None
    # Per-attempt PoV-runner Wilson-bound reliability, if measured.
    pov_reliability: float | None = Field(default=None, ge=0.0, le=1.0)

    # True when this turn was a judge-v2 verify turn (the bounded
    # drill-down re-probe of a prior ``needs_followup`` claim). Sourced
    # from ``metadata.get("verify") is True`` at construction time. Used
    # by the aggregator to dedupe identical-verdict verify turns (see
    # design §III.C).
    is_verify_turn: bool = False

    # The turn's ``summary`` (the judge's reasoning, capped to ~480 chars).
    # Surfaces on the representative Attempt's ``Finding.summary`` as a
    # fallback when no LLM-synthesised rollup is available.
    summary: str = ""

    # Frozen so an aggregated Attempt list cannot be mutated out from under
    # the Finding it backs. ``extra="ignore"`` so legacy on-disk payloads
    # round-trip without raising if a future field shows up.
    model_config = ConfigDict(frozen=True, extra="ignore")
