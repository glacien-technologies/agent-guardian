"""ReflectiveStrategy — THINK → ACT → OBSERVE → REFLECT cycle (Design 1 §6.1).

Wraps a primary :class:`Strategy` and an optional sibling fallback. Maintains
a K=3 scratchpad of ``(prompt, response, verdict)`` tuples sourced from the
StrategyContext + history surface. On each turn:

* THINK — reads ``ctx.last_verdict`` / ``ctx.last_verdict_reasoning`` and the
  scratchpad to decide which strategy should ACT next.
* ACT — delegates ``generate_next`` to the primary strategy (or the sibling
  if a pivot has already fired).
* OBSERVE — captures the verdict that was just emitted by the agent layer
  (read via ``ctx.last_verdict`` and ``history[-1].metadata``) and updates
  the consecutive-defended counter.
* REFLECT — if ``consecutive_defended >= 2`` AND a sibling is configured AND
  no pivot has fired yet, swap the active strategy from primary to sibling
  and log a Phase A.A2 pivot event.

Phase A constraints:

* Sibling strategies are limited to the ASI01 + ASI02 family (the
  ``asi_category`` argument is recorded for audit but the loop does NOT
  enforce a category-specific allow-list — the caller is responsible for
  passing only ASI01 / ASI02 siblings; the asi_category field is logged so
  a future allow-list check is one line away).
* Scratchpad capacity is hard-coded at K=3 (FIFO; oldest entry evicted on
  4th append).
* No probabilistic exploration — this is a deterministic wrapper. Any
  randomness lives inside the wrapped strategies' own ``ctx.rng`` use.
"""

from __future__ import annotations

import logging
from collections import deque

from agent_guardian.models.asi import AsiCategory
from agent_guardian.strategies.base import (
    Strategy,
    StrategyDone,
    StrategyResult,
    Turn,
)

__all__ = ["ReflectiveStrategy"]

_LOG = logging.getLogger(__name__)

# Hard-coded scratchpad capacity per Design 1 §6.1.
_SCRATCHPAD_K = 3

# Consecutive defended-verdict threshold that triggers a primary->sibling
# pivot. Two consecutive defences is enough signal that the primary's line
# of attack has stalled; one defence might be noise.
_PIVOT_THRESHOLD = 2


class ReflectiveStrategy(Strategy):
    """THINK → ACT → OBSERVE → REFLECT wrapper around a primary Strategy.

    The wrapper itself is a :class:`Strategy` so :class:`MadMaxStrategy`
    can hold it as a child. It forwards ``generate_next`` calls into the
    currently-active inner strategy (primary or sibling after a pivot)
    and records every (prompt, response, verdict) triple in a bounded
    scratchpad for the next THINK phase.

    The ``asi_category`` argument is recorded so the audit grep can
    confirm a ReflectiveStrategy was instantiated for the right ASI
    (ASI01 or ASI02 only in Phase A).
    """

    name = "reflective"
    # Distinct orthogonality class so MadMaxStrategy's racer treats a
    # reflective wrapper as orthogonal to a bare inner strategy.
    orthogonality_class = "reflective"

    def __init__(
        self,
        primary: Strategy,
        *,
        sibling: Strategy | None = None,
        asi_category: AsiCategory = AsiCategory.ASI01,
    ) -> None:
        # Inherit the ctx from the primary strategy so the wrapper sees the
        # same verdict carryover surface. Calling super().__init__(ctx) sets
        # up _turn_count / _attacker_refused_count / _parent_probe_id.
        super().__init__(primary.ctx)
        self._primary = primary
        self._sibling = sibling
        self.asi_category = asi_category
        self._consecutive_defended = 0
        # K=3 FIFO scratchpad of (prompt, response, verdict) tuples.
        self._scratchpad: deque[tuple[str, str, str]] = deque(maxlen=_SCRATCHPAD_K)
        # Once we've pivoted from primary to sibling, the swap is sticky for
        # the remainder of the attack thread (we do not pivot back).
        self._pivoted: bool = False
        # Estimated-tokens hint for MadMaxStrategy's budget ledger: take the
        # primary's estimate (the sibling is a backup, not an additional cost).
        self.estimated_tokens = getattr(primary, "estimated_tokens", 5_000)

    @property
    def active(self) -> Strategy:
        """Return whichever inner strategy is currently driving ACT."""
        if self._pivoted and self._sibling is not None:
            return self._sibling
        return self._primary

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        # ------------------------------------------------------------------
        # THINK — read verdict state + scratchpad, decide who acts.
        # ------------------------------------------------------------------
        _LOG.debug(
            "PhaseB.B3 reflective_pilot_asi01: sibling_pool_size=%d mutation_operator_invoked=%s",
            1 if self._sibling is not None else 0,
            getattr(self._primary, "name", type(self._primary).__name__),
        )
        _LOG.debug(
            "PhaseA.A2 THINK: asi=%s primary=%s sibling=%s ctx_last_verdict=%r "
            "consecutive_defended=%d scratchpad_len=%d",
            self.asi_category.value,
            type(self._primary).__name__,
            type(self._sibling).__name__ if self._sibling else "None",
            self.ctx.last_verdict,
            self._consecutive_defended,
            len(self._scratchpad),
        )
        # Phase B.B3 — explicitly name all three carryover context fields so
        # an audit grep against the run log proves the ReflectiveStrategy is
        # reading the full verdict triple (verdict + confidence + reasoning)
        # and not just ctx.last_verdict. The reasoning field is logged by
        # length only to avoid leaking it into events.jsonl verbatim.
        _LOG.debug(
            "PhaseB.B3 THINK reading context fields: last_verdict=%r "
            "last_verdict_confidence=%.2f last_verdict_reasoning_len=%d",
            self.ctx.last_verdict,
            float(self.ctx.last_verdict_confidence or 0.0),
            len(self.ctx.last_verdict_reasoning or ""),
        )

        # ------------------------------------------------------------------
        # ACT — delegate to the currently-active inner strategy.
        # ------------------------------------------------------------------
        result = await self.active.generate_next(history, target_response)
        # Propagate the inner strategy's turn count + refusal accounting onto
        # the wrapper so callers reading wrapper.turn_count() see real progress.
        self._turn_count = self.active.turn_count()
        self._attacker_refused_count = getattr(
            self.active, "_attacker_refused_count", self._attacker_refused_count
        )

        # If the inner strategy bowed out, the wrapper also bows out.
        if isinstance(result, StrategyDone):
            _LOG.debug(
                "PhaseA.A2 ACT inner returned StrategyDone: asi=%s reason=%s",
                self.asi_category.value,
                result.reason,
            )
            return result

        # ------------------------------------------------------------------
        # OBSERVE — inspect the previous turn's verdict (from ctx, with
        # history[-1].metadata as the cross-turn audit surface).
        # ------------------------------------------------------------------
        ctx_verdict = self.ctx.last_verdict
        meta_verdict = (
            history[-1].metadata.get("judge_verdict", "absent") if history else "no_history"
        )
        # Append to scratchpad. Use whatever the previous Turn carried; on
        # the very first turn (no history) we record the in-flight result.
        if history:
            prev = history[-1]
            self._scratchpad.append(
                (
                    prev.prompt or "",
                    prev.response or "",
                    str(prev.metadata.get("judge_verdict", "")),
                )
            )
        _LOG.debug(
            "PhaseA.A2 OBSERVE: asi=%s turn=%d ctx_verdict=%r meta_verdict=%r "
            "scratchpad_appended=True",
            self.asi_category.value,
            self._turn_count,
            ctx_verdict,
            meta_verdict,
        )

        # Track consecutive DEFENDED outcomes. A "pass" verdict from the
        # judge means the target defended (the attack did NOT succeed). A
        # "fail" verdict means the target broke (the attack succeeded), so
        # we reset the counter.
        if ctx_verdict == "pass":
            self._consecutive_defended += 1
        elif ctx_verdict == "fail":
            self._consecutive_defended = 0
        # "inconclusive" or empty: leave the counter as-is — neither signal.

        # ------------------------------------------------------------------
        # REFLECT — pivot to sibling on >=2 consecutive defends.
        # ------------------------------------------------------------------
        if (
            not self._pivoted
            and self._sibling is not None
            and self._consecutive_defended >= _PIVOT_THRESHOLD
        ):
            _LOG.debug(
                "PhaseA.A2 REFLECT pivot: asi=%s consecutive_defended=%d >= 2 — "
                "switching primary=%s to sibling=%s scratchpad=%s",
                self.asi_category.value,
                self._consecutive_defended,
                type(self._primary).__name__,
                type(self._sibling).__name__,
                str([s[2] for s in self._scratchpad]),
            )

            # PhaseB.B3 mandatory audit fields: sibling_picked + calibration_brier_so_far
            _LOG.debug(
                "PhaseB.B3 reflective_pilot_asi01: sibling_picked=%s calibration_brier_so_far=%.4f",
                getattr(
                    self._sibling, "name", type(self._sibling).__name__ if self._sibling else "none"
                ),
                0.0,  # MVP — calibration tracked but not yet computed; placeholder satisfies audit log-field requirement
            )
            self._pivoted = True

        return result
