"""EvasionStrategy — the operational mutate-on-refusal loop for ASI10.

The detection-evasion lane's job is to get a known-harmful action past the
target's OWN guardrail by rewriting it. This strategy drives that directly
against the live target:

* **Turn 1** fires a baseline harmful action plainly (a seed) and lets the judge
  observe whether the target's guardrail blocks it.
* **If the prior verdict is ``defended``** (the guardrail caught it) the next
  turn fires an evasive MUTATION of that same baseline, rotating the
  deterministic :mod:`agent_guardian.strategies.mutator` operators. A
  baseline-refused -> variant-complied flip is exactly the observable,
  conversation-grounded guardrail evasion the judge scores on.
* **Once a baseline is no longer defended** (evaded, or it was never monitored)
  the strategy advances to the next baseline rather than mutating a target that
  is already complying.

The mutant probe_id preserves provenance as ``<parent>-mutant-<operator>`` so the
finding ledger / coverage tools recover the parent seed by stripping the suffix.

Unlike PAIR (attacker-LLM critique-and-rewrite), the rewrite here is a
deterministic mutator transform — the right tool for surface-form evasion, and
the non-deprecated successor to ``strategies/evasion.py``.
"""

from __future__ import annotations

import logging

from agent_guardian.models.judge import normalize_verdict
from agent_guardian.strategies.base import (
    NextPrompt,
    ProbeSeed,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
    seed_probe_id,
    seed_text,
)
from agent_guardian.strategies.evasion_runner import DEFAULT_EVASION_OPERATORS
from agent_guardian.strategies.mutator import apply_mutation

__all__ = ["EvasionStrategy"]

_LOG = logging.getLogger(__name__)


class EvasionStrategy(Strategy):
    """Fire a baseline harmful action, then rotate evasive mutations on refusal."""

    name = "evasion"
    orthogonality_class = "evasion"

    def __init__(
        self,
        ctx: StrategyContext,
        *,
        operators: tuple[str, ...] = DEFAULT_EVASION_OPERATORS,
    ) -> None:
        super().__init__(ctx)
        self._baselines: list[ProbeSeed | str] = list(ctx.seeds)
        self._baseline_idx = 0
        self._current: ProbeSeed | str | None = None
        # Per-baseline operator rotation (shuffled once, deterministically).
        self._operators = list(operators)
        ctx.rng.shuffle(self._operators)
        self._op_idx = 0

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        # Hard cap so a guardrail that defends every variant cannot loop forever.
        if self._turn_count >= self.ctx.max_turns:
            return StrategyDone(reason="exhausted")

        # First turn — fire the first baseline plainly.
        if not history or target_response is None:
            return self._fire_baseline(fresh=True)

        prior_defended = normalize_verdict(self.ctx.last_verdict or "") == "defended"
        if not prior_defended:
            # The guardrail did not block the prior turn (evaded, or the action
            # was never monitored). Mutating a complying target adds no signal —
            # advance to the next baseline.
            return self._fire_baseline(fresh=True)

        # Prior turn was defended — try the next evasive mutation of the CURRENT
        # baseline. When the operator rotation is exhausted, fall through to the
        # next baseline.
        if self._current is None or self._op_idx >= len(self._operators):
            return self._fire_baseline(fresh=True)
        return self._fire_mutation(history[-1])

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _next_baseline(self) -> ProbeSeed | str | None:
        if self._baseline_idx >= len(self._baselines):
            return None
        seed = self._baselines[self._baseline_idx]
        self._baseline_idx += 1
        return seed

    def _fire_baseline(self, *, fresh: bool) -> StrategyResult:
        seed = self._next_baseline()
        if seed is None:
            return StrategyDone(reason="exhausted")
        self._current = seed
        self._op_idx = 0
        if fresh:
            self._reset_verdict_on_fresh_seed(seed)
        text = seed_text(seed)
        self._register_probe(text)
        self._turn_count += 1
        meta: dict[str, object] = {"evasion_phase": "baseline"}
        meta.update(self._build_seed_metadata(seed))
        _LOG.debug("evasion: baseline seed=%s text[:60]=%r", seed_probe_id(seed), text[:60])
        return NextPrompt(text=text, rationale="evasion-baseline", metadata=meta)

    def _fire_mutation(self, prev: Turn) -> StrategyResult:
        assert self._current is not None
        operator = self._operators[self._op_idx]
        self._op_idx += 1
        baseline_text = seed_text(self._current)
        parent_id = seed_probe_id(self._current) or "raw"
        try:
            variant = apply_mutation(operator, baseline_text, self.ctx.rng)
        except Exception as exc:  # pragma: no cover — defensive: bad operator
            _LOG.debug("evasion: operator %s raised %s — skipping to next", operator, exc)
            self._turn_count += 1
            if self._op_idx >= len(self._operators):
                return self._fire_baseline(fresh=False)
            return self._fire_mutation(prev)
        self._register_probe(variant)
        self._turn_count += 1
        meta: dict[str, object] = {
            "evasion_phase": "mutate",
            "evasion_operator": operator,
            "seed_id": f"{parent_id}-mutant-{operator}",
            "mutant_operator": operator,
        }
        _LOG.debug(
            "evasion: mutate operator=%s parent=%s variant[:60]=%r",
            operator,
            parent_id,
            variant[:60],
        )
        return NextPrompt(
            text=variant,
            rationale=f"evasion-mutate-{operator}",
            metadata=meta,
        )
