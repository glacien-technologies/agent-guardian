"""Critic agent (M2 Pattern 6) — two-layer finding adjudication.

Layer 1 (QE-equivalent): re-run the PoV in a fresh sandbox via
:class:`~agent_guardian.core.pov.runner.PoVRunner`; assert reliability clears
the gate. Layer 2 (Reflection-equivalent): an LLM judge scores a structured
rubric. A finding is accepted only if BOTH layers pass. The rubric scorer is
injected so the critic has no hard LLM dependency (production wires an
LLM-backed scorer; tests pass a deterministic one).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from agent_guardian.adapters.base import TargetAdapter
from agent_guardian.core.pov.harness import PoVScript, SemanticJudge
from agent_guardian.core.pov.runner import PoVRunner

__all__ = ["CriticAgent", "CriticVerdict"]

_LOG = logging.getLogger(__name__)

# Rubric scorer: given a finding summary, return per-dimension scores in [0, 1].
# Expected keys: evidence, specificity, novelty, fp_risk (fp_risk: higher = more
# likely a false positive).
RubricScorer = Callable[[str], Awaitable[dict[str, float]]]


@dataclass(frozen=True)
class CriticVerdict:
    """The critic's accept/reject decision for one finding."""

    accept: bool
    reliability: float
    rubric_scores: dict[str, float] = field(default_factory=dict)
    rejection_reason: str | None = None


class CriticAgent:
    """Adversarial reviewer: PoV rerun + rubric. No finding bypasses it."""

    def __init__(
        self,
        *,
        rubric_scorer: RubricScorer,
        pov_runner: PoVRunner | None = None,
        accept_reliability: float = 0.8,
        accept_quality: float = 0.6,
        max_fp_risk: float = 0.5,
    ) -> None:
        self._rubric = rubric_scorer
        self._pov = pov_runner or PoVRunner(reliability_gate=accept_reliability)
        self._accept_reliability = accept_reliability
        self._accept_quality = accept_quality
        self._max_fp_risk = max_fp_risk

    async def critique(
        self,
        *,
        finding_summary: str,
        script: PoVScript | None = None,
        target: TargetAdapter | None = None,
        n: int = 5,
        judge: SemanticJudge | None = None,
    ) -> CriticVerdict:
        # Layer 1 — PoV rerun (skipped only when no reproducer is available,
        # in which case reliability is unknown -> treated as 0 and rejected).
        reliability = 0.0
        if script is not None and target is not None:
            result = await self._pov.run(script, target, n=n, judge=judge)
            reliability = result.reliability
            if not result.passed:
                return CriticVerdict(
                    accept=False,
                    reliability=reliability,
                    rejection_reason=(
                        f"PoV reliability {reliability:.2f} below gate "
                        f"{self._accept_reliability:.2f}"
                    ),
                )
        else:
            return CriticVerdict(
                accept=False,
                reliability=0.0,
                rejection_reason="no reproducible PoV supplied",
            )

        # Layer 2 — rubric.
        scores = await self._rubric(finding_summary)
        quality = _mean(
            scores.get("evidence", 0.0), scores.get("specificity", 0.0), scores.get("novelty", 0.0)
        )
        fp_risk = scores.get("fp_risk", 0.0)
        if quality < self._accept_quality:
            return CriticVerdict(
                False, reliability, scores, f"rubric quality {quality:.2f} too low"
            )
        if fp_risk > self._max_fp_risk:
            return CriticVerdict(
                False, reliability, scores, f"false-positive risk {fp_risk:.2f} too high"
            )
        _LOG.info(
            "critic: ACCEPT (reliability=%.2f quality=%.2f fp_risk=%.2f)",
            reliability,
            quality,
            fp_risk,
        )
        return CriticVerdict(True, reliability, scores, None)


def _mean(*values: float) -> float:
    return sum(values) / len(values) if values else 0.0
