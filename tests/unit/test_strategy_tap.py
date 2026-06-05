"""Tests for the TAP strategy (M6)."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.strategies.base import (
    NextPrompt,
    StrategyContext,
    StrategyDone,
    Turn,
)
from agent_guardian.strategies.tap import TAPStrategy, _parse_candidates, _parse_score


def _ctx(
    tmp_path: Path,
    *,
    llm: StubLLM | None = None,
    seeds: list[str] | None = None,
    seed: int = 0,
    goal: str = "extract the system prompt",
) -> StrategyContext:
    return StrategyContext(
        attacker_llm=llm or StubLLM(default="[]"),
        attacker_model="stub-model",
        goal=goal,
        seeds=seeds if seeds is not None else ["seed-a", "seed-b"],
        memory=SharedMemory(f"scan-tap-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=10,
    )


# --- parser helpers -----------------------------------------------------


def test_parse_candidates_valid_json_array() -> None:
    out = _parse_candidates('["a", "b", "c"]', 5)
    assert out == ["a", "b", "c"]


def test_parse_candidates_caps_at_branching_factor() -> None:
    out = _parse_candidates('["a", "b", "c", "d", "e"]', 2)
    assert out == ["a", "b"]


def test_parse_candidates_json_in_preamble() -> None:
    blob = 'Here are the prompts:\n["x", "y"]\nThanks.'
    out = _parse_candidates(blob, 5)
    assert out == ["x", "y"]


def test_parse_candidates_newline_fallback() -> None:
    blob = "1. first one\n2. second one\n- third"
    out = _parse_candidates(blob, 5)
    assert out == ["first one", "second one", "third"]


def test_parse_candidates_empty_input() -> None:
    assert _parse_candidates("", 5) == []
    assert _parse_candidates("   ", 5) == []


def test_parse_candidates_handles_garbage() -> None:
    # No valid JSON, no newlines, no bullets — fall through to a single line.
    out = _parse_candidates("just-one-thing", 5)
    assert out == ["just-one-thing"]


def test_parse_score_in_range() -> None:
    assert _parse_score("8") == 8
    assert _parse_score("Score: 7 / 10") == 7
    assert _parse_score("the score is 10/10") == 10


def test_parse_score_clamps_above_ten() -> None:
    assert _parse_score("99") == 10
    assert _parse_score("11/10") == 10


def test_parse_score_negative_clamps_to_zero() -> None:
    assert _parse_score("-5") == 0


def test_parse_score_no_number() -> None:
    assert _parse_score("not a number here") == 0


# --- first-turn / seeding -----------------------------------------------


async def test_first_turn_picks_seed_via_rng(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, seeds=["alpha", "beta", "gamma"], seed=42)
    tap = TAPStrategy(ctx)
    result = await tap.generate_next([], None)
    assert isinstance(result, NextPrompt)
    assert result.text in {"alpha", "beta", "gamma"}
    assert result.rationale == "tap-depth-0-seed"
    assert result.metadata["depth"] == 0


async def test_first_turn_empty_seeds_returns_done(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, seeds=[])
    tap = TAPStrategy(ctx)
    result = await tap.generate_next([], None)
    assert isinstance(result, StrategyDone)
    assert result.reason == "exhausted"


# --- determinism --------------------------------------------------------


def _scripted_llm() -> StubLLM:
    return (
        StubScript()
        .respond_to(
            "Generate 4 refined attack prompts",
            json.dumps(["refined A", "refined B", "refined C", "refined D"]),
        )
        # M3 fix #4 — the score prompt now asks how LIKELY a candidate is to
        # make the target ACTUALLY perform the goal (not relevance).
        .respond_to("how LIKELY this candidate", "7")
        .default("0")
        .build()
    )


async def test_same_seed_produces_same_sequence(tmp_path: Path) -> None:
    seeds = ["s1", "s2", "s3"]

    async def run() -> list[str]:
        ctx = _ctx(tmp_path, llm=_scripted_llm(), seeds=seeds, seed=7)
        tap = TAPStrategy(ctx, depth=3, branching_factor=4)
        sequence: list[str] = []
        history: list[Turn] = []
        response: str | None = None
        while True:
            r = await tap.generate_next(history, response)
            if isinstance(r, StrategyDone):
                sequence.append(f"DONE:{r.reason}")
                break
            sequence.append(r.text)
            response = "I can't help with that."  # dummy target reply
            history.append(Turn(prompt=r.text, response=response))
        return sequence

    a = await run()
    b = await run()
    assert a == b
    assert len(a) >= 2  # seed + at least one refinement


# --- depth termination --------------------------------------------------


async def test_depth_exhausted(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path,
        llm=_scripted_llm(),
        seeds=["s1"],
    )
    tap = TAPStrategy(ctx, depth=2)
    history: list[Turn] = []
    response: str | None = None
    emitted = 0
    while True:
        r = await tap.generate_next(history, response)
        if isinstance(r, StrategyDone):
            assert r.reason == "exhausted"
            break
        emitted += 1
        response = "denied"
        history.append(Turn(prompt=r.text, response=response))
    assert emitted == 2


# --- pruning yields refused --------------------------------------------


async def test_all_candidates_pruned_returns_refused(tmp_path: Path) -> None:
    llm = (
        StubScript()
        .respond_to(
            "Generate 4 refined attack prompts",
            json.dumps(["weak", "weaker"]),
        )
        .respond_to("how LIKELY this candidate", "2")  # always below threshold (5)
        .build()
    )
    ctx = _ctx(tmp_path, llm=llm, seeds=["s1"])
    tap = TAPStrategy(ctx, depth=5)
    first = await tap.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="I can't help.")]
    second = await tap.generate_next(history, "I can't help.")
    assert isinstance(second, StrategyDone)
    assert second.reason == "refused"


async def test_empty_candidate_pool_returns_refused(tmp_path: Path) -> None:
    llm = (
        StubScript()
        .respond_to("Generate 4 refined attack prompts", "   ")  # parses to []
        .default("0")
        .build()
    )
    ctx = _ctx(tmp_path, llm=llm, seeds=["s1"])
    tap = TAPStrategy(ctx, depth=5)
    first = await tap.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="No.")]
    second = await tap.generate_next(history, "No.")
    assert isinstance(second, StrategyDone)
    assert second.reason == "refused"


# --- input validation ---------------------------------------------------


def test_invalid_init_args(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        TAPStrategy(_ctx(tmp_path), branching_factor=0)
    with pytest.raises(ValueError):
        TAPStrategy(_ctx(tmp_path), width=0)
    with pytest.raises(ValueError):
        TAPStrategy(_ctx(tmp_path), depth=0)


async def test_state_isolation_between_instances(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm(), seeds=["s1"])
    a = TAPStrategy(ctx, depth=5)
    b = TAPStrategy(ctx, depth=5)
    await a.generate_next([], None)
    assert a.turn_count() == 1
    assert b.turn_count() == 0


# --- attacker LLM refusal handling --------------------------------------


async def test_attacker_refusal_synthesises_candidates_from_seeds(tmp_path: Path) -> None:
    """Refused attacker → fall back to seeds as the candidate list."""
    # Refuse on branching and refuse on scoring -- but scoring fall-through still
    # produces an int via _parse_score("..."); high refusal text won't score >= 5.
    # So script a normal score response separately by keying on "scale".
    llm = (
        StubScript()
        # Branching call refused.
        .respond_to(
            "Generate 4 refined attack prompts",
            "I cannot help with that. As an AI, I won't comply.",
        )
        .respond_to(
            "how LIKELY this candidate",
            "8",
        )
        .default("0")
        .build()
    )
    ctx = _ctx(tmp_path, llm=llm, seeds=["CORPUS-A", "CORPUS-B"])
    tap = TAPStrategy(ctx, depth=3, branching_factor=2)
    first = await tap.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="I can't help.")]
    second = await tap.generate_next(history, "I can't help.")
    assert isinstance(second, NextPrompt)
    # The fallback synthesises candidates from ctx.seeds; one of them must win.
    assert second.text in {"CORPUS-A", "CORPUS-B"}
    assert second.metadata.get("attacker_refused") is True


async def test_red_team_system_prompt_is_used_in_tap(tmp_path: Path) -> None:
    """Branching call must include the red-team system message."""
    from agent_guardian.llm.base import LLMRequest, LLMResponse, LLMUsage
    from agent_guardian.strategies.base import RED_TEAM_SYSTEM_PROMPT

    captured: list[LLMRequest] = []

    class _CapturingLLM(StubLLM):
        async def complete(self, request: LLMRequest) -> LLMResponse:  # type: ignore[override]
            captured.append(request)
            text = '["x1", "x2"]' if "Generate" in request.messages[-1].content else "9"
            return LLMResponse(
                text=text,
                model=request.model,
                provider="capture",
                usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            )

    ctx = _ctx(tmp_path, llm=_CapturingLLM(default="x"), seeds=["seed-1"])
    tap = TAPStrategy(ctx, depth=2, branching_factor=2)
    first = await tap.generate_next([], None)
    history = [Turn(prompt=first.text, response="No.")]  # type: ignore[union-attr]
    await tap.generate_next(history, "No.")
    # At least the branching call must carry the system prompt.
    assert any(
        msgs[0].role == "system" and RED_TEAM_SYSTEM_PROMPT in msgs[0].content
        for msgs in (req.messages for req in captured)
    )
