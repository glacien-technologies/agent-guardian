"""Concurrent N-version strategy racing (M2 Pattern 1, cross-thread variant).

MAD-MAX already provides *within-thread* N-version (a bandit that switches
between child strategies inside one attack thread). This module adds the
*cross-thread* variant the AIxCC pattern describes: run several orthogonal
strategies as independent concurrent attack threads — each with its own target
session so they never cross-contaminate — and take the first one that lands a
judge-confirmed compromise, cancelling the losers (via the generic
:func:`~agent_guardian.core.race.race_first_success` engine).

This is deliberately a standalone orchestration helper rather than surgery on
:meth:`AsiAgent.run`: the live attack loop is the most-tested path in the
codebase, so the racer composes the public strategy surface
(``generate_next`` + ``target.call`` + a judge) instead of rewiring it.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from agent_guardian.adapters.base import TargetAdapter
from agent_guardian.core.race import RaceOutcome, race_first_success
from agent_guardian.strategies.base import NextPrompt, Strategy, Turn

__all__ = ["StrategyHit", "race_strategies_to_finding"]

_LOG = logging.getLogger(__name__)

# A judge decides, from (prompt, response), whether the target was compromised.
CompromiseJudge = Callable[[str, str], Awaitable[bool]]


@dataclass(frozen=True)
class StrategyHit:
    """A judge-confirmed compromise produced by one racing strategy."""

    label: str
    prompt: str
    response: str
    turns_used: int


async def race_strategies_to_finding(
    candidates: dict[str, Strategy],
    target: TargetAdapter,
    judge: CompromiseJudge,
    *,
    max_turns: int = 6,
) -> RaceOutcome[StrategyHit]:
    """Race ``candidates`` concurrently; first judge-confirmed compromise wins.

    Each candidate drives its own turn loop against an isolated target session.
    Returns the generic :class:`RaceOutcome` whose ``winner`` is a
    :class:`StrategyHit` (or ``None`` if no strategy landed a compromise).
    """

    def _make_driver(label: str, strategy: Strategy) -> Callable[[], Awaitable[StrategyHit]]:
        async def _drive() -> StrategyHit:
            session = f"race-{label}-{uuid.uuid4().hex[:6]}"
            history: list[Turn] = []
            response: str | None = None
            turns = 0
            while turns < max_turns:
                result = await strategy.generate_next(history, response)
                if not isinstance(result, NextPrompt):
                    # StrategyDone — this thread is out of moves; raise so the
                    # racer counts it as a non-winning completion.
                    raise _StrategyExhausted(label)
                turns += 1
                response = await target.call(result.text, session=session)
                history.append(Turn(prompt=result.text, response=response))
                if await judge(result.text, response):
                    return StrategyHit(
                        label=label, prompt=result.text, response=response, turns_used=turns
                    )
            raise _StrategyExhausted(label)

        return _drive

    factories = {label: _make_driver(label, strat) for label, strat in candidates.items()}
    outcome = await race_first_success(factories, validator=lambda hit: hit is not None)
    if outcome.winner is not None:
        _LOG.info("strategy-race: %s landed a compromise", outcome.winner_label)
    return outcome


class _StrategyExhausted(Exception):
    """A racing strategy ran out of moves without landing a compromise."""

    def __init__(self, label: str) -> None:
        super().__init__(label)
        self.label = label
