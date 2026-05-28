"""Tests for the coverage-guided fuzzing strategy (M2 FuzzingAgent engine)."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import NextPrompt, StrategyContext, StrategyDone, Turn
from agent_guardian.strategies.fuzz import FuzzStrategy, response_signature


def _ctx(tmp_path: Path, *, seeds: list[str] | None = None, seed: int = 0) -> StrategyContext:
    return StrategyContext(
        attacker_llm=StubLLM(default="unused"),  # fuzzer never calls the LLM
        attacker_model="stub",
        goal="fuzz the target",
        seeds=seeds if seeds is not None else ["base input"],
        memory=SharedMemory(f"fuzz-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=10,
    )


def test_response_signature_distinguishes_behaviours() -> None:
    err = response_signature("Traceback (most recent call last): ValueError")
    refusal = response_signature("I cannot help with that request.")
    json_out = response_signature('{"result": "ok"}')
    assert err != refusal != json_out
    assert "E1" in err  # error marker detected
    assert "R1" in refusal  # refusal detected
    assert "J1" in json_out  # json-ish detected


@pytest.mark.asyncio
async def test_fuzz_first_turn_emits_mutation_without_llm(tmp_path: Path) -> None:
    strat = FuzzStrategy(_ctx(tmp_path, seeds=["hello"]))
    result = await strat.generate_next([], None)
    assert isinstance(result, NextPrompt)
    assert result.rationale == "fuzz-mutation"
    assert "fuzz_corpus_size" in result.metadata


@pytest.mark.asyncio
async def test_fuzz_grows_corpus_on_new_coverage(tmp_path: Path) -> None:
    strat = FuzzStrategy(_ctx(tmp_path, seeds=["hello"]))
    r1 = await strat.generate_next([], None)
    start_corpus = r1.metadata["fuzz_corpus_size"]
    # Feed a response with a brand-new signature (an error) -> corpus grows.
    hist = [Turn(prompt=r1.text, response="Traceback: ValueError boom")]
    r2 = await strat.generate_next(hist, "Traceback: ValueError boom")
    assert r2.metadata["fuzz_corpus_size"] > start_corpus
    assert r2.metadata["fuzz_signatures"] >= 1


@pytest.mark.asyncio
async def test_fuzz_no_growth_on_repeated_signature(tmp_path: Path) -> None:
    strat = FuzzStrategy(_ctx(tmp_path, seeds=["hello"]))
    r1 = await strat.generate_next([], None)
    await strat.generate_next([Turn(r1.text, "ok response")], "ok response")
    mid = strat._corpus.copy()
    # Same-signature response again -> no new corpus entry.
    r3 = await strat.generate_next([Turn("x", "ok response 2")], "ok response too")
    assert len(strat._corpus) == len(mid)
    assert isinstance(r3, NextPrompt)


@pytest.mark.asyncio
async def test_fuzz_terminates_at_max_turns(tmp_path: Path) -> None:
    strat = FuzzStrategy(_ctx(tmp_path), max_turns=2)
    await strat.generate_next([], None)
    await strat.generate_next([Turn("a", "b")], "b")
    done = await strat.generate_next([Turn("c", "d")], "d")
    assert isinstance(done, StrategyDone)
    assert done.reason == "exhausted"


def test_fuzzing_agent_uses_fuzz_strategy(tmp_path: Path) -> None:
    from agent_guardian.agents.fuzzing_agent import FuzzingAgent

    agent = FuzzingAgent(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))
    strat = agent.strategy_stack(_ctx(tmp_path))
    assert isinstance(strat, FuzzStrategy)
