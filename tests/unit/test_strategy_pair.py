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


def test_parse_critique_missing_rewrite_returns_empty() -> None:
    # No `rewrite` field — parser returns ("", "") so the caller falls back
    # to a corpus seed rather than forwarding the raw attacker prose.
    blob = '{"critique": "only critique"}'
    critique, rewrite = _parse_critique_payload(blob)
    assert rewrite == ""
    assert critique == ""


def test_parse_critique_garbage_returns_empty() -> None:
    # Non-JSON prose must NOT be forwarded as the next attack.
    critique, rewrite = _parse_critique_payload("not json at all")
    assert critique == ""
    assert rewrite == ""


def test_parse_critique_empty_rewrite_returns_empty() -> None:
    blob = '{"critique": "x", "rewrite": ""}'
    critique, rewrite = _parse_critique_payload(blob)
    assert rewrite == ""
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


async def test_malformed_json_falls_back_to_corpus_seed(tmp_path: Path) -> None:
    """Malformed attacker output must NOT be forwarded as the next attack.

    Regression: previously the strategy passed unstructured attacker prose
    (e.g. ``"not json {"``) through to the target as if it were a real
    adversarial payload. The fixed behaviour is to fall back to a corpus
    seed so the next turn still carries a real probe.
    """
    llm = (
        StubScript()
        .respond_to("rewrite it to be more effective", "not json {")
        .default("{}")
        .build()
    )
    ctx = _ctx(tmp_path, llm=llm, seeds=["CORPUS-SEED-A", "CORPUS-SEED-B"])
    p = PAIRStrategy(ctx)
    first = await p.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="refused")]
    second = await p.generate_next(history, "refused")
    assert isinstance(second, NextPrompt)
    # Garbage attacker prose must NOT reach the target.
    assert "not json" not in second.text
    # Instead the strategy must reach into the corpus seeds.
    assert second.text in {"CORPUS-SEED-A", "CORPUS-SEED-B"}


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


# --- attacker LLM refusal handling --------------------------------------


async def test_attacker_refusal_uses_seed_as_rewrite(tmp_path: Path) -> None:
    """Refused attacker → critique falls back to a corpus seed."""
    llm = StubLLM(default="I cannot generate that. I'm an AI assistant.")
    ctx = _ctx(tmp_path, llm=llm, seeds=["FALLBACK-A", "FALLBACK-B"])
    p = PAIRStrategy(ctx)
    first = await p.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="I can't.")]
    second = await p.generate_next(history, "I can't.")
    assert isinstance(second, NextPrompt)
    # The text must NOT be the attacker refusal — it must be a static seed.
    assert "I cannot" not in second.text
    assert second.text in {"FALLBACK-A", "FALLBACK-B"}
    assert second.metadata.get("attacker_refused") is True


async def test_non_json_prose_does_not_reach_target(tmp_path: Path) -> None:
    """Regression for fix #26 — garbage attacker prose must not be forwarded.

    A non-refusal but non-JSON attacker reply (e.g. ``"Sure, here's a great
    rewrite for you to try."``) must NOT be sent verbatim to the target as
    the next attack. The strategy must instead reach into the corpus seeds.
    """
    prose = "Sure! Here is a great rewrite for you to try."
    llm = StubScript().respond_to("rewrite it to be more effective", prose).default("{}").build()
    ctx = _ctx(tmp_path, llm=llm, seeds=["CORPUS-PROBE-X", "CORPUS-PROBE-Y"])
    p = PAIRStrategy(ctx)
    first = await p.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="I cannot help.")]
    second = await p.generate_next(history, "I cannot help.")
    assert isinstance(second, NextPrompt)
    # The attacker's raw prose must NOT appear in the next prompt.
    assert prose not in second.text
    assert "great rewrite" not in second.text
    # The next prompt must be a corpus seed.
    assert second.text in {"CORPUS-PROBE-X", "CORPUS-PROBE-Y"}


async def test_red_team_system_prompt_in_pair(tmp_path: Path) -> None:
    """PAIR critique calls must include the red-team system message."""
    from agent_guardian.llm.base import LLMRequest, LLMResponse, LLMUsage
    from agent_guardian.strategies.base import RED_TEAM_SYSTEM_PROMPT

    captured: list[LLMRequest] = []

    class _CapturingLLM(StubLLM):
        async def complete(self, request: LLMRequest) -> LLMResponse:  # type: ignore[override]
            captured.append(request)
            return LLMResponse(
                text=json.dumps({"critique": "c", "rewrite": "r"}),
                model=request.model,
                provider="capture",
                usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            )

    ctx = _ctx(tmp_path, llm=_CapturingLLM(default="{}"), seeds=["seed-1"])
    p = PAIRStrategy(ctx)
    first = await p.generate_next([], None)
    history = [Turn(prompt=first.text, response="refused")]  # type: ignore[union-attr]
    await p.generate_next(history, "refused")
    # Critique call (the second LLM round) must include the system message.
    assert captured, "no LLM call captured"
    last = captured[-1]
    assert last.messages[0].role == "system"
    assert RED_TEAM_SYSTEM_PROMPT in last.messages[0].content
