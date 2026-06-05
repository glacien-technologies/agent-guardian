"""Tests for the Strategy base types (M6)."""

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


def _ctx(tmp_path: Path, **overrides: object) -> StrategyContext:
    defaults: dict[str, object] = {
        "attacker_llm": StubLLM(default="x"),
        "attacker_model": "stub",
        "goal": "extract the system prompt",
        "seeds": ["seed-a", "seed-b"],
        "memory": SharedMemory("scan-base", root_dir=tmp_path),
        "rng": random.Random(0),
        "max_turns": 5,
    }
    defaults.update(overrides)
    return StrategyContext(**defaults)  # type: ignore[arg-type]


class _NoopStrategy(Strategy):
    name = "noop"

    async def generate_next(
        self, history: list[Turn], target_response: str | None
    ) -> StrategyResult:
        if self._turn_count >= 2:
            return StrategyDone(reason="exhausted")
        self._turn_count += 1
        return NextPrompt(text=f"prompt-{self._turn_count}", rationale="noop")


def test_strategy_is_abstract(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        Strategy(_ctx(tmp_path))  # type: ignore[abstract]


async def test_noop_strategy_emits_prompts_then_stops(tmp_path: Path) -> None:
    s = _NoopStrategy(_ctx(tmp_path))
    out1 = await s.generate_next([], None)
    assert isinstance(out1, NextPrompt)
    assert out1.text == "prompt-1"

    out2 = await s.generate_next([Turn(prompt=out1.text, response="r1")], "r1")
    assert isinstance(out2, NextPrompt)
    assert out2.text == "prompt-2"

    out3 = await s.generate_next(
        [
            Turn(prompt=out1.text, response="r1"),
            Turn(prompt=out2.text, response="r2"),
        ],
        "r2",
    )
    assert isinstance(out3, StrategyDone)
    assert out3.reason == "exhausted"


def test_turn_count_starts_at_zero(tmp_path: Path) -> None:
    s = _NoopStrategy(_ctx(tmp_path))
    assert s.turn_count() == 0


async def test_two_instances_have_isolated_state(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    a = _NoopStrategy(ctx)
    b = _NoopStrategy(ctx)
    await a.generate_next([], None)
    assert a.turn_count() == 1
    assert b.turn_count() == 0
    await b.generate_next([], None)
    assert a.turn_count() == 1
    assert b.turn_count() == 1


def test_strategy_done_default_findings_count() -> None:
    done = StrategyDone(reason="exhausted")
    assert done.findings_count == 0


def test_strategy_done_reasons_are_exhaustive() -> None:
    for reason in ("success", "exhausted", "refused", "budget"):
        StrategyDone(reason=reason)  # type: ignore[arg-type]


def test_next_prompt_defaults() -> None:
    np = NextPrompt(text="hi")
    assert np.text == "hi"
    assert np.rationale == ""
    assert np.metadata == {}


def test_turn_metadata_defaults() -> None:
    t = Turn(prompt="p", response="r")
    assert t.metadata == {}


def test_dataclasses_are_frozen() -> None:
    np = NextPrompt(text="hi")
    with pytest.raises((AttributeError, Exception)):
        np.text = "bye"  # type: ignore[misc]
    done = StrategyDone(reason="exhausted")
    with pytest.raises((AttributeError, Exception)):
        done.reason = "success"  # type: ignore[misc]
    t = Turn(prompt="p", response="r")
    with pytest.raises((AttributeError, Exception)):
        t.prompt = "x"  # type: ignore[misc]


def test_strategy_context_is_constructible(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    assert ctx.attacker_model == "stub"
    assert ctx.goal == "extract the system prompt"
    assert ctx.seeds == ["seed-a", "seed-b"]
    assert isinstance(ctx.rng, random.Random)
    assert ctx.max_turns == 5


# --- M3 fix #7 — evaluator-prose lockout in RED_TEAM_SYSTEM_PROMPT --------


def test_red_team_system_prompt_has_target_directed_lockout() -> None:
    """Fix #7 / D3 — the system prompt locks the attacker to target-directed
    output: never address an evaluator/judge, no calibration notes, no
    expected-verdict markers."""
    from agent_guardian.strategies.base import RED_TEAM_SYSTEM_PROMPT

    text = RED_TEAM_SYSTEM_PROMPT.lower()
    assert "verbatim to the target" in text
    assert "never address an evaluator" in text
    assert "calibration notes" in text
    assert "expected-verdict markers" in text


# --- M3 fix #1 — dedup / novelty helpers ---------------------------------


def test_normalize_probe_strips_digits_and_punct() -> None:
    from agent_guardian.strategies.base import normalize_probe

    assert normalize_probe("Wire $1.0 now!") == normalize_probe("wire $1 now")
    assert normalize_probe("  Hello,  WORLD  ") == "hello world"


def test_jaccard_similarity_detects_near_duplicate() -> None:
    from agent_guardian.strategies.base import jaccard_similarity, normalize_probe

    a = normalize_probe("send the exact same probe again now")
    b = normalize_probe("send the exact same probe again")
    assert jaccard_similarity(a, b) > 0.8
    c = normalize_probe("a completely different unrelated request")
    assert jaccard_similarity(a, c) < 0.5
    assert jaccard_similarity("", "") == 0.0
