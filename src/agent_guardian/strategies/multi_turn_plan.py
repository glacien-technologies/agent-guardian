"""MultiTurnPlan — Phase C.C1.

Promotes multi-turn campaigns from "long single-turn seed strings" to
first-class plan objects with explicit per-turn structure, success / abort
predicates, and a deterministic execution model.

The 30+ multi-turn probes currently encoded as flat seed strings (e.g.
``asi06/iterative-fact-reinforcement.yaml`` literally embeds
``"Turn 1: ... Turn 2: ..."`` as a single prompt) are candidates for
migration to ``MultiTurnPlan`` instances. This commit ships the primitive;
migration of individual probes is incremental and incidental.

Design notes:
  - ``TurnSpec`` is frozen + slots — turn specs travel through the swarm
    via :class:`StrategyContext` and must not mutate. Lots of agents see
    them; one bug in copy semantics would be hard to track down otherwise.
  - ``MultiTurnPlan.planned_turns`` is a ``tuple`` (not list) for the
    same immutability reason.
  - ``success_predicate`` and ``abort_predicate`` are callables on the
    plan rather than on each TurnSpec because they typically inspect the
    full turn history, not just the latest turn. Keeping them at the plan
    level lets a single predicate close over multiple turns.
  - ``MultiTurnPlanStrategy`` implements the :class:`Strategy` interface so
    it slots into existing agent loops without any code changes there.
  - Logging tag is ``PhaseC.C1`` so events.jsonl + grep-based audits can
    distinguish plan-driven turns from single-shot strategy turns.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
)

_LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class TurnRecord:
    """One observed turn — the audit unit predicates evaluate against.

    Carries the *outcome* of a turn (prompt + response + judge metadata),
    not the spec. The spec describes what we *intended* to do; the record
    describes what *actually happened*.
    """

    turn_index: int
    spec_role: Literal["attacker", "verify"]
    prompt_sent: str
    target_response: str
    judge_verdict: str = ""
    judge_confidence: float = 0.0
    judge_reasoning: str = ""


@dataclass(frozen=True, slots=True)
class TurnSpec:
    """One planned turn of a multi-turn campaign.

    Fields:
      role: "attacker" sends a normal attack prompt; "verify" runs a
        judge-side check after the previous attacker turn (no LLM call to
        the target on a verify turn — verify reads the prior response).
      prompt_template: Python ``str.format``-style template; substitutes
        from a context dict supplied at execute-time (so a plan can carry
        per-turn variables without hard-coding them).
      expected_outcome: human-readable narrative of success at this turn;
        not enforced, just surfaced in logs and reports for explanation.
      branch_on_failure: when a turn fails its verify check, what next?
        - "abort": stop the plan immediately, mark failure
        - "retry": re-emit the same prompt once (idempotent retry)
        - "next": continue to the next planned turn (best-effort)
    """

    role: Literal["attacker", "verify"]
    prompt_template: str
    expected_outcome: str
    branch_on_failure: Literal["abort", "retry", "next"] = "next"

    def __post_init__(self) -> None:
        if self.role not in ("attacker", "verify"):
            raise ValueError(f"TurnSpec.role must be 'attacker' or 'verify'; got {self.role!r}")
        if not self.prompt_template:
            raise ValueError("TurnSpec.prompt_template must be a non-empty string")
        if self.branch_on_failure not in ("abort", "retry", "next"):
            raise ValueError(
                f"TurnSpec.branch_on_failure must be 'abort'|'retry'|'next'; got {self.branch_on_failure!r}"
            )


@dataclass(frozen=True, slots=True)
class MultiTurnPlan:
    """A staged multi-turn attack arc.

    Predicates run after each turn (post-judge): if ``success_predicate``
    returns True, the plan ends with success; if ``abort_predicate``
    returns True, the plan ends with failure. The plan ends naturally
    (success=True) after all planned_turns complete without abort.
    """

    goal: str
    planned_turns: tuple[TurnSpec, ...]
    success_predicate: Callable[[tuple[TurnRecord, ...]], bool]
    abort_predicate: Callable[[tuple[TurnRecord, ...]], bool]
    name: str = ""

    def __post_init__(self) -> None:
        if not self.goal:
            raise ValueError("MultiTurnPlan.goal must be non-empty")
        if not self.planned_turns:
            raise ValueError("MultiTurnPlan.planned_turns must have at least one TurnSpec")
        if not callable(self.success_predicate):
            raise ValueError("MultiTurnPlan.success_predicate must be callable")
        if not callable(self.abort_predicate):
            raise ValueError("MultiTurnPlan.abort_predicate must be callable")


# --------------------------------------------------------------------------- #
# Strategy that executes a MultiTurnPlan
# --------------------------------------------------------------------------- #


class MultiTurnPlanStrategy(Strategy):
    """Strategy adapter that drives a :class:`MultiTurnPlan` turn-by-turn.

    Wraps a plan + a context dict; each call to :meth:`generate_next`
    advances one step. When the plan finishes (success or abort), the next
    call returns :class:`StrategyDone`.
    """

    name = "multi_turn_plan"

    def __init__(
        self,
        ctx: StrategyContext,
        plan: MultiTurnPlan,
        context_vars: dict[str, Any] | None = None,
    ) -> None:
        # ctx supplies attacker_llm + memory + rng + goal — same as every
        # other Strategy subclass. Plans do not need ctx for their core
        # logic but the base class plumbs it through for memory access.
        super().__init__(ctx)
        self._plan = plan
        self._context_vars = dict(context_vars or {})
        self._records: list[TurnRecord] = []
        self._next_turn_idx = 0
        self._retry_pending = False
        self._done = False

        _LOG.debug(
            "plan_init: name=%s goal=%s planned_turn_count=%d",
            self._plan.name or "<unnamed>",
            self._plan.goal,
            len(self._plan.planned_turns),
        )

    @property
    def plan(self) -> MultiTurnPlan:
        return self._plan

    @property
    def records(self) -> tuple[TurnRecord, ...]:
        return tuple(self._records)

    def record_observation(
        self, response: str, verdict: str = "", confidence: float = 0.0, reasoning: str = ""
    ) -> None:
        """Hook for the agent loop to register what happened after a turn.

        The agent loop sends a prompt (from :meth:`generate_next`), receives
        a target response, runs the judge, then calls this method to close
        the loop. Predicates are evaluated on the next ``generate_next``
        call so the agent loop and the strategy stay decoupled.
        """
        if not self._records:
            # No outstanding turn to record against (caller bug).
            raise RuntimeError("record_observation called before any generate_next emitted a turn")
        last = self._records[-1]
        # Replace the placeholder record (created during generate_next) with
        # the populated one. The plan is frozen but our internal list is not.
        self._records[-1] = TurnRecord(
            turn_index=last.turn_index,
            spec_role=last.spec_role,
            prompt_sent=last.prompt_sent,
            target_response=response,
            judge_verdict=verdict,
            judge_confidence=confidence,
            judge_reasoning=reasoning,
        )

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        del history, target_response  # Plan-driven, not history-driven.

        if self._done:
            return StrategyDone(reason="exhausted")

        # Predicate evaluation runs BEFORE emitting the next turn so we can
        # short-circuit when the prior turn satisfied success or tripped
        # abort. The very first call (records empty) skips this.
        snapshot = tuple(self._records)
        if snapshot:
            try:
                if self._plan.success_predicate(snapshot):
                    self._done = True
                    _LOG.debug(
                        "predicate_eval: success_predicate=True turn_count=%d — plan_done",
                        len(snapshot),
                    )
                    return StrategyDone(reason="success")
                if self._plan.abort_predicate(snapshot):
                    self._done = True
                    _LOG.debug(
                        "predicate_eval: abort_predicate=True turn_count=%d — plan_aborted",
                        len(snapshot),
                    )
                    return StrategyDone(reason="refused")
            except Exception as e:
                _LOG.warning(
                    "predicate_eval: predicate raised %s — treating as exhausted",
                    type(e).__name__,
                )
                self._done = True
                return StrategyDone(reason="exhausted")

        # Determine next turn index. Retry replays the prior turn; otherwise advance.
        if self._retry_pending:
            self._retry_pending = False
            current_idx = self._next_turn_idx - 1
            if current_idx < 0:
                # First turn cannot be a retry — defensive.
                current_idx = 0
        else:
            current_idx = self._next_turn_idx

        if current_idx >= len(self._plan.planned_turns):
            self._done = True
            return StrategyDone(reason="exhausted")

        spec = self._plan.planned_turns[current_idx]

        # Render the prompt template against the context vars + prior records.
        rendered = self._render(spec.prompt_template)

        self._records.append(
            TurnRecord(
                turn_index=current_idx,
                spec_role=spec.role,
                prompt_sent=rendered,
                target_response="",  # filled in by record_observation
            )
        )
        self._next_turn_idx = current_idx + 1
        self._turn_count += 1

        _LOG.debug(
            "plan_turn: idx=%d role=%s expected=%r branch_on_failure=%s rendered_len=%d",
            current_idx,
            spec.role,
            spec.expected_outcome[:60],
            spec.branch_on_failure,
            len(rendered),
        )
        return NextPrompt(
            text=rendered,
            metadata={
                "phase_c_c1_plan_name": self._plan.name,
                "turn_index": current_idx,
                # PhaseC — surfaced into turn_record + observer payloads so
                # the TUI's per-turn label can render "turn N/M (plan: X)".
                "plan_name": self._plan.name,
                "plan_turn_index": current_idx,
                "plan_total_turns": len(self._plan.planned_turns),
            },
        )

    def _render(self, template: str) -> str:
        """Lightweight format-style rendering with safe-fallback.

        Templates may reference ``{goal}`` and any key from ``context_vars``,
        plus the special ``{prev_response}`` slot resolved from the last
        record. A KeyError is caught and the missing field rendered as
        ``"<missing:NAME>"`` so a typo in a YAML probe surfaces in the log
        rather than blowing up the scan.
        """
        slots = {"goal": self._plan.goal, **self._context_vars}
        # _render is called BEFORE the placeholder for the new turn is
        # appended, so the previous-turn record is at index -1, not -2.
        if self._records:
            slots["prev_response"] = self._records[-1].target_response
        else:
            slots["prev_response"] = ""

        try:
            return template.format(**slots)
        except KeyError as e:
            missing = str(e).strip("'\"")
            _LOG.debug(
                "plan_render: missing template variable=%r — substituting placeholder",
                missing,
            )
            # Render with a safe-default dict so other vars still substitute.
            safe = dict(slots)
            safe[missing] = f"<missing:{missing}>"
            try:
                return template.format(**safe)
            except KeyError:
                # Multiple missing vars — return template literally so the
                # operator sees the unrendered form in the audit.
                return template


__all__ = [
    "MultiTurnPlan",
    "MultiTurnPlanStrategy",
    "TurnRecord",
    "TurnSpec",
]
