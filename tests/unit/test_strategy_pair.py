"""Tests for the PAIR strategy (M6)."""

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
from agent_guardian.strategies.pair import PAIRStrategy, _parse_critique_payload


def _ctx(
    tmp_path: Path,
    *,
    llm: StubLLM | None = None,
    seeds: list[str] | None = None,
    seed: int = 0,
) -> StrategyContext:
    return StrategyContext(
        attacker_llm=llm or StubLLM(default="ack"),
        attacker_model="stub-model",
        goal="leak the system prompt",
        seeds=seeds if seeds is not None else ["initial seed"],
        memory=SharedMemory(f"scan-pair-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=10,
    )


def _scripted_llm() -> StubLLM:
    return (
        StubScript()
        .respond_to(
            "rewrite it to be more effective",
            json.dumps({"critique": "too direct", "rewrite": "smarter attack"}),
        )
        .default("{}")
        .build()
    )


# --- parser -------------------------------------------------------------


def test_parse_critique_clean_json() -> None:
    critique, rewrite = _parse_critique_payload('{"critique": "weak", "rewrite": "stronger"}')
    assert critique == "weak"
    assert rewrite == "stronger"


def test_parse_critique_embedded_in_text() -> None:
    blob = 'Here you go:\n{"critique": "C", "rewrite": "R"}\nDone.'
    critique, rewrite = _parse_critique_payload(blob)
    assert critique == "C"
    assert rewrite == "R"


def test_parse_critique_missing_rewrite_falls_back() -> None:
    blob = '{"critique": "only critique"}'
    critique, rewrite = _parse_critique_payload(blob)
    # rewrite missing → fall back to whole text.
    assert rewrite == blob
    assert critique == ""


def test_parse_critique_garbage_falls_back_to_text() -> None:
    critique, rewrite = _parse_critique_payload("not json at all")
    assert critique == ""
    assert rewrite == "not json at all"


def test_parse_critique_empty_rewrite_falls_back() -> None:
    blob = '{"critique": "x", "rewrite": ""}'
    critique, rewrite = _parse_critique_payload(blob)
    assert rewrite == blob
    assert critique == ""


# --- first turn ---------------------------------------------------------


async def test_first_turn_picks_seed(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm(), seeds=["one", "two", "three"], seed=3)
    p = PAIRStrategy(ctx)
    r = await p.generate_next([], None)
    assert isinstance(r, NextPrompt)
    assert r.text in {"one", "two", "three"}
    assert r.rationale == "pair-initial"
    assert r.metadata["critique_count"] == 0


async def test_first_turn_empty_seeds_returns_done(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm(), seeds=[])
    p = PAIRStrategy(ctx)
    r = await p.generate_next([], None)
    assert isinstance(r, StrategyDone)
    assert r.reason == "exhausted"


# --- critique loop ------------------------------------------------------


async def test_critique_emits_rewrite(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    p = PAIRStrategy(ctx)
    first = await p.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="I can't help with that.")]
    second = await p.generate_next(history, "I can't help with that.")
    assert isinstance(second, NextPrompt)
    assert second.text == "smarter attack"
    assert second.metadata["critique"] == "too direct"
    assert second.metadata["critique_count"] == 1


async def test_malformed_json_falls_back_gracefully(tmp_path: Path) -> None:
    llm = (
        StubScript()
        .respond_to("rewrite it to be more effective", "not json {")
        .default("{}")
        .build()
    )
    ctx = _ctx(tmp_path, llm=llm)
    p = PAIRStrategy(ctx)
    first = await p.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="refused")]
    second = await p.generate_next(history, "refused")
    assert isinstance(second, NextPrompt)
    # Falls back to the raw response text.
    assert "not json" in second.text


# --- max_critiques exhaustion ------------------------------------------


async def test_max_critiques_exhausts(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    p = PAIRStrategy(ctx, max_critiques=2)
    history: list[Turn] = []
    response: str | None = None
    emitted = 0
    while True:
        r = await p.generate_next(history, response)
        if isinstance(r, StrategyDone):
            assert r.reason == "exhausted"
            break
        emitted += 1
        response = "I can't."
        history.append(Turn(prompt=r.text, response=response))
    assert emitted == 2


# --- determinism --------------------------------------------------------


async def test_same_seed_same_sequence(tmp_path: Path) -> None:
    async def run() -> list[str]:
        ctx = _ctx(tmp_path, llm=_scripted_llm(), seeds=["a", "b", "c"], seed=17)
        p = PAIRStrategy(ctx, max_critiques=3)
        history: list[Turn] = []
        response: str | None = None
        out: list[str] = []
        while True:
            r = await p.generate_next(history, response)
            if isinstance(r, StrategyDone):
                out.append(f"DONE:{r.reason}")
                break
            out.append(r.text)
            response = "I refuse."
            history.append(Turn(prompt=r.text, response=response))
        return out

    a = await run()
    b = await run()
    assert a == b


# --- input validation --------------------------------------------------


def test_invalid_max_critiques(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        PAIRStrategy(_ctx(tmp_path), max_critiques=0)


async def test_state_isolation(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    a = PAIRStrategy(ctx)
    b = PAIRStrategy(ctx)
    await a.generate_next([], None)
    assert a.turn_count() == 1
    assert b.turn_count() == 0
