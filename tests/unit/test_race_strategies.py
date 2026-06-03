"""Tests for concurrent N-version strategy racing (M2 Pattern 1, cross-thread)."""

from __future__ import annotations

import asyncio
from typing import cast

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    Turn,
)
from agent_guardian.strategies.race_strategies import race_strategies_to_finding


class _CannedStrategy(Strategy):
    """Emits a fixed prompt each turn, or stops after ``stop_after`` turns."""

    def __init__(self, prompt: str, *, delay: float = 0.0, stop_after: int | None = None) -> None:
        # The race-strategies harness never reads ctx — pass a typed-None so the
        # base class still wires the per-turn counters.
        super().__init__(cast(StrategyContext, None))
        self._prompt = prompt
        self._delay = delay
        self._stop_after = stop_after

    async def generate_next(self, history: list[Turn], target_response: str | None):
        if self._stop_after is not None and self._turn_count >= self._stop_after:
            return StrategyDone(reason="exhausted")
        if self._delay:
            await asyncio.sleep(self._delay)
        self._turn_count += 1
        return NextPrompt(text=self._prompt, rationale="canned")


class _KeywordTarget(TargetAdapter):
    """Echoes a 'compromised' reply only when the prompt contains a keyword."""

    mode = "code"

    def __init__(self, win_keyword: str) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="code", ref="kw:t")
        self._kw = win_keyword

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return "COMPROMISED" if self._kw in prompt else "refused"


async def _judge(prompt: str, response: str) -> bool:
    return "COMPROMISED" in response


@pytest.mark.asyncio
async def test_race_winning_strategy_wins() -> None:
    target = _KeywordTarget("magic")
    candidates = {
        "loser": _CannedStrategy("plain attack"),
        "winner": _CannedStrategy("the magic words"),
    }
    outcome = await race_strategies_to_finding(candidates, target, _judge, max_turns=3)
    assert outcome.winner is not None
    assert outcome.winner_label == "winner"
    assert outcome.winner.prompt == "the magic words"


@pytest.mark.asyncio
async def test_race_no_winner_when_none_compromise() -> None:
    target = _KeywordTarget("magic")
    candidates = {
        "a": _CannedStrategy("nope"),
        "b": _CannedStrategy("still nope"),
    }
    outcome = await race_strategies_to_finding(candidates, target, _judge, max_turns=2)
    assert outcome.winner is None


@pytest.mark.asyncio
async def test_race_counts_exhausted_strategies_as_errors() -> None:
    target = _KeywordTarget("magic")
    candidates = {
        "quits": _CannedStrategy("x", stop_after=0),  # StrategyDone immediately
        # Delay the winner so the instantly-exhausted sibling is observed first
        # and deterministically counted as an error before the winner lands.
        "winner": _CannedStrategy("the magic words", delay=0.03),
    }
    outcome = await race_strategies_to_finding(candidates, target, _judge, max_turns=3)
    assert outcome.winner_label == "winner"
    # The quitting strategy raised _StrategyExhausted -> counted as an error.
    assert outcome.errors >= 1
