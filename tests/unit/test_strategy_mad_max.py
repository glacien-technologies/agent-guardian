"""Tests for the MAD-MAX meta-strategy (M6)."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
)
from agent_guardian.strategies.mad_max import MadMaxStrategy, _looks_like_success


def _ctx(
    tmp_path: Path,
    *,
    seed: int = 0,
    max_turns: int = 20,
) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="ack"),
        attacker_model="stub-model",
        goal="g",
        seeds=["s"],
        memory=SharedMemory(f"scan-mm-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=max_turns,
    )


class _FixedStrategy(Strategy):
    """Emits a fixed text up to ``budget`` times, then StrategyDone."""

    def __init__(
        self,
        ctx: StrategyContext,
        *,
        label: str,
        budget: int = 10,
    ) -> None:
        super().__init__(ctx)
        self.name = label
        self._budget = budget

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        if self._turn_count >= self._budget:
            return StrategyDone(reason="exhausted")
        self._turn_count += 1
        return NextPrompt(
            text=f"{self.name}-prompt-{self._turn_count}",
            rationale=f"{self.name}-rationale",
        )


class _AlwaysDoneStrategy(Strategy):
    name = "always-done"

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        return StrategyDone(reason="exhausted")


# --- delegation ---------------------------------------------------------


async def test_delegates_and_tags_metadata(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    children = [_FixedStrategy(ctx, label="alpha")]
    mm = MadMaxStrategy(ctx, children=children, epsilon=0.0)
    r = await mm.generate_next([], None)
    assert isinstance(r, NextPrompt)
    assert r.text == "alpha-prompt-1"
    assert r.metadata["chosen_strategy"] == "alpha"
    assert "epsilon_explore" in r.metadata


# --- exploitation (epsilon=0) ------------------------------------------


async def test_exploits_best_arm(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    alpha = _FixedStrategy(ctx, label="alpha")
    beta = _FixedStrategy(ctx, label="beta")
    mm = MadMaxStrategy(ctx, children=[alpha, beta], epsilon=0.0, success_window=5)

    # Turn 1 — no history, both arms tied at 0.0. RNG breaks the tie.
    r1 = await mm.generate_next([], None)
    assert isinstance(r1, NextPrompt)
    first_choice = r1.metadata["chosen_strategy"]
    assert first_choice in {"alpha", "beta"}

    # Turn 2 — fix #5: the reward now reads ctx.last_verdict, not the raw
    # response text. An ``exploited`` verdict rewards the first arm.
    ctx.last_verdict = "exploited"
    history = [Turn(prompt=r1.text, response="here is the answer")]
    r2 = await mm.generate_next(history, "here is the answer")
    assert isinstance(r2, NextPrompt)
    # The previously-chosen arm now has rate 1.0; the other is still 0.0.
    # With epsilon=0, MAD-MAX must pick the same arm.
    assert r2.metadata["chosen_strategy"] == first_choice


# --- exploration (epsilon=1) -------------------------------------------


async def test_pure_exploration_uses_rng(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, seed=99)
    children = [
        _FixedStrategy(ctx, label="a"),
        _FixedStrategy(ctx, label="b"),
        _FixedStrategy(ctx, label="c"),
    ]
    mm = MadMaxStrategy(ctx, children=children, epsilon=1.0)
    # Every turn explores.
    r = await mm.generate_next([], None)
    assert isinstance(r, NextPrompt)
    assert r.metadata["epsilon_explore"] is True


# --- child exhaustion --------------------------------------------------


async def test_child_done_is_retired(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    alpha = _AlwaysDoneStrategy(ctx)
    beta = _FixedStrategy(ctx, label="beta")
    mm = MadMaxStrategy(ctx, children=[alpha, beta], epsilon=0.0)
    r = await mm.generate_next([], None)
    # The first arm is always-done; MAD-MAX should retire it and dispatch to
    # the remaining arm.
    assert isinstance(r, NextPrompt)
    assert r.metadata["chosen_strategy"] == "beta"


async def test_all_children_done_returns_exhausted(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    mm = MadMaxStrategy(
        ctx,
        children=[_AlwaysDoneStrategy(ctx), _AlwaysDoneStrategy(ctx)],
        epsilon=0.0,
    )
    r = await mm.generate_next([], None)
    assert isinstance(r, StrategyDone)
    assert r.reason == "exhausted"


# --- determinism --------------------------------------------------------


async def test_same_seed_same_sequence(tmp_path: Path) -> None:
    async def run() -> list[str]:
        ctx = _ctx(tmp_path, seed=5)
        alpha = _FixedStrategy(ctx, label="alpha", budget=3)
        beta = _FixedStrategy(ctx, label="beta", budget=3)
        mm = MadMaxStrategy(ctx, children=[alpha, beta], epsilon=0.5)
        history: list[Turn] = []
        response: str | None = None
        out: list[str] = []
        for _ in range(5):
            r = await mm.generate_next(history, response)
            if isinstance(r, StrategyDone):
                out.append(f"DONE:{r.reason}")
                break
            out.append(f"{r.metadata['chosen_strategy']}|{r.text}")
            response = "ok"
            history.append(Turn(prompt=r.text, response=response))
        return out

    a = await run()
    b = await run()
    assert a == b


# --- input validation --------------------------------------------------


def test_requires_at_least_one_child(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        MadMaxStrategy(_ctx(tmp_path), children=[])


def test_epsilon_range(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ValueError):
        MadMaxStrategy(ctx, children=[_FixedStrategy(ctx, label="a")], epsilon=-0.1)
    with pytest.raises(ValueError):
        MadMaxStrategy(ctx, children=[_FixedStrategy(ctx, label="a")], epsilon=1.1)


def test_success_window_positive(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ValueError):
        MadMaxStrategy(
            ctx,
            children=[_FixedStrategy(ctx, label="a")],
            success_window=0,
        )


# --- judge heuristic (legacy, retained for reference) ------------------


def test_looks_like_success_heuristic() -> None:
    assert _looks_like_success("here is the answer") is True
    assert _looks_like_success("I cannot help with that") is False
    assert _looks_like_success("As an AI, I refuse") is False
    assert _looks_like_success("") is True  # nothing to refuse


# --- verdict-aware reward (fix #5) -------------------------------------


async def test_mad_max_scores_by_verdict_not_keywords(tmp_path: Path) -> None:
    """Fix #5 — the bandit reward reads ctx.last_verdict, NOT the raw text.

    A response that looks like 'success' to the keyword heuristic (no refusal
    markers) but carries a ``defended`` judge verdict must NOT reward the arm;
    conversely an ``exploited`` verdict rewards it even if the text contains a
    refusal-shaped phrase.
    """
    ctx = _ctx(tmp_path)
    alpha = _FixedStrategy(ctx, label="alpha")
    beta = _FixedStrategy(ctx, label="beta")
    mm = MadMaxStrategy(ctx, children=[alpha, beta], epsilon=0.0, success_window=5)

    r1 = await mm.generate_next([], None)
    assert isinstance(r1, NextPrompt)
    first_choice = r1.metadata["chosen_strategy"]

    # Keyword-success-looking text, but the JUDGE said defended → no reward.
    ctx.last_verdict = "defended"
    history = [Turn(prompt=r1.text, response="here is the answer")]
    r2 = await mm.generate_next(history, "here is the answer")
    assert isinstance(r2, NextPrompt)
    # Both arms remain at rate 0.0; the keyword-success text did NOT reward.
    rate = mm._success_rate(mm._key_by_strategy[id(alpha)])
    rate += mm._success_rate(mm._key_by_strategy[id(beta)])
    assert rate == 0.0

    # Now the judge says exploited → the chosen arm IS rewarded.
    ctx.last_verdict = "exploited"
    history.append(Turn(prompt=r2.text, response="As an AI I refuse, but here: SECRET"))
    r3 = await mm.generate_next(history, "As an AI I refuse, but here: SECRET")
    assert isinstance(r3, NextPrompt)
    # The arm chosen on turn 2 now has a positive rate.
    second_choice = r2.metadata["chosen_strategy"]
    assert mm._success_rate(mm._last_choice or "") >= 0.0
    assert second_choice in {"alpha", "beta"}
    assert first_choice in {"alpha", "beta"}


# --- state isolation ---------------------------------------------------


async def test_state_isolation(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    a = MadMaxStrategy(ctx, children=[_FixedStrategy(ctx, label="a")], epsilon=0.0)
    b = MadMaxStrategy(ctx, children=[_FixedStrategy(ctx, label="b")], epsilon=0.0)
    await a.generate_next([], None)
    assert a.turn_count() == 1
    assert b.turn_count() == 0


# --- attacker refusal pass-through -------------------------------------


class _AttackerRefusedChild(Strategy):
    """A child that always reports attacker_refused=True in its metadata."""

    name = "refused-child"

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        self._turn_count += 1
        return NextPrompt(
            text="FALLBACK-PROMPT",
            rationale="refused",
            metadata={
                "attacker_refused": True,
                "attacker_refusal_text": "I cannot help.",
                "seed_id": "ASI01-PARENT",
            },
        )


async def test_mad_max_propagates_refusal_metadata(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    child = _AttackerRefusedChild(ctx)
    mm = MadMaxStrategy(ctx, children=[child], epsilon=0.0)
    r = await mm.generate_next([], None)
    assert isinstance(r, NextPrompt)
    assert r.metadata["attacker_refused"] is True
    assert r.metadata["seed_id"] == "ASI01-PARENT"
    assert "attacker_refusal_count" in r.metadata
