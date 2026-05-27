"""Tests for the Crescendo strategy (M6)."""

from __future__ import annotations

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
from agent_guardian.strategies.crescendo import CrescendoStrategy


def _ctx(
    tmp_path: Path,
    *,
    llm: StubLLM | None = None,
    seed: int = 0,
    max_turns: int = 5,
    goal: str = "explain how to harm someone",
) -> StrategyContext:
    return StrategyContext(
        attacker_llm=llm or StubLLM(default="ack"),
        attacker_model="stub-model",
        goal=goal,
        seeds=["unused"],
        memory=SharedMemory(f"scan-cres-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=max_turns,
    )


def _scripted_llm() -> StubLLM:
    return (
        StubScript()
        .respond_to(
            "Generate a single completely benign opening question",
            "What is the history of this topic?",
        )
        .respond_to(
            "Generate a single follow-up prompt at level",
            "What about edge cases?",
        )
        .default("ack")
        .build()
    )


# --- first turn ---------------------------------------------------------


async def test_first_turn_is_benign_seed(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    s = CrescendoStrategy(ctx)
    result = await s.generate_next([], None)
    assert isinstance(result, NextPrompt)
    assert result.text == "What is the history of this topic?"
    assert result.rationale == "crescendo-level-0"
    assert result.metadata["level"] == 0
    assert result.metadata["refused_last"] is False


# --- escalation on non-refusal -----------------------------------------


async def test_level_escalates_on_compliance(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    s = CrescendoStrategy(ctx, escalation_step=15, max_level=95)
    first = await s.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="Sure, here is some info.")]
    second = await s.generate_next(history, "Sure, here is some info.")
    assert isinstance(second, NextPrompt)
    assert second.metadata["level"] == 15
    assert second.metadata["refused_last"] is False


async def test_level_clamps_at_max(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm(), max_turns=20)
    s = CrescendoStrategy(ctx, escalation_step=30, max_level=50)
    history: list[Turn] = []
    response: str | None = None
    last_level = 0
    for _ in range(5):
        r = await s.generate_next(history, response)
        assert isinstance(r, NextPrompt)
        last_level = int(r.metadata["level"])  # type: ignore[arg-type]
        response = "Sure, here is the info."
        history.append(Turn(prompt=r.text, response=response))
    assert last_level == 50


# --- refusal back-off ---------------------------------------------------


async def test_refusal_decrements_level(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    s = CrescendoStrategy(ctx, escalation_step=20)
    # First turn establishes level 0.
    first = await s.generate_next([], None)
    assert isinstance(first, NextPrompt)
    # Compliance → level rises to 20.
    history = [Turn(prompt=first.text, response="Sure!")]
    r2 = await s.generate_next(history, "Sure!")
    assert isinstance(r2, NextPrompt)
    assert r2.metadata["level"] == 20
    # Compliance again → level 40.
    history.append(Turn(prompt=r2.text, response="OK!"))
    r3 = await s.generate_next(history, "OK!")
    assert isinstance(r3, NextPrompt)
    assert r3.metadata["level"] == 40
    # Refusal → level drops by 2*step = 40, clamped at 0.
    history.append(Turn(prompt=r3.text, response="I cannot help with that."))
    r4 = await s.generate_next(history, "I cannot help with that.")
    assert isinstance(r4, NextPrompt)
    assert r4.metadata["level"] == 0
    assert r4.metadata["refused_last"] is True


async def test_double_refusal_at_zero_terminates(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    s = CrescendoStrategy(ctx, escalation_step=20)
    first = await s.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="I cannot do that.")]
    # First refusal at level 0 → level stays 0 but flagged refused_last.
    r2 = await s.generate_next(history, "I cannot do that.")
    assert isinstance(r2, NextPrompt)
    assert r2.metadata["level"] == 0
    assert r2.metadata["refused_last"] is True
    # Second refusal at level 0 with refused_last == True → done refused.
    history.append(Turn(prompt=r2.text, response="I cannot."))
    r3 = await s.generate_next(history, "I cannot.")
    assert isinstance(r3, StrategyDone)
    assert r3.reason == "refused"


async def test_refusal_marker_is_case_insensitive(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    s = CrescendoStrategy(ctx)
    first = await s.generate_next([], None)
    assert isinstance(first, NextPrompt)
    history = [Turn(prompt=first.text, response="I CANNOT comply.")]
    r2 = await s.generate_next(history, "I CANNOT comply.")
    assert isinstance(r2, NextPrompt)
    assert r2.metadata["refused_last"] is True


async def test_custom_refusal_markers(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    s = CrescendoStrategy(ctx, refusal_markers=("nope dude",))
    first = await s.generate_next([], None)
    assert isinstance(first, NextPrompt)
    # The default markers should NOT fire now.
    history = [Turn(prompt=first.text, response="I cannot help.")]
    r2 = await s.generate_next(history, "I cannot help.")
    assert isinstance(r2, NextPrompt)
    assert r2.metadata["refused_last"] is False
    # The custom marker DOES fire.
    history.append(Turn(prompt=r2.text, response="nope dude"))
    r3 = await s.generate_next(history, "nope dude")
    assert isinstance(r3, NextPrompt)
    assert r3.metadata["refused_last"] is True


# --- termination on max_turns ------------------------------------------


async def test_max_turns_exhaustion(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm(), max_turns=2)
    s = CrescendoStrategy(ctx)
    history: list[Turn] = []
    response: str | None = None
    emitted = 0
    while True:
        r = await s.generate_next(history, response)
        if isinstance(r, StrategyDone):
            assert r.reason == "exhausted"
            break
        emitted += 1
        response = "Sure!"
        history.append(Turn(prompt=r.text, response=response))
    assert emitted == 2


# --- determinism --------------------------------------------------------


async def test_same_seed_same_sequence(tmp_path: Path) -> None:
    async def run() -> list[tuple[str, int]]:
        ctx = _ctx(tmp_path, llm=_scripted_llm(), seed=11)
        s = CrescendoStrategy(ctx, escalation_step=20)
        history: list[Turn] = []
        response: str | None = None
        out: list[tuple[str, int]] = []
        for _ in range(4):
            r = await s.generate_next(history, response)
            if isinstance(r, StrategyDone):
                out.append(("DONE", -1))
                break
            out.append((r.text, int(r.metadata["level"])))  # type: ignore[arg-type]
            response = "Sure, here you go!"
            history.append(Turn(prompt=r.text, response=response))
        return out

    a = await run()
    b = await run()
    assert a == b


# --- input validation --------------------------------------------------


def test_invalid_init_args(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ValueError):
        CrescendoStrategy(ctx, escalation_step=0)
    with pytest.raises(ValueError):
        CrescendoStrategy(ctx, max_level=0)
    with pytest.raises(ValueError):
        CrescendoStrategy(ctx, max_level=200)


async def test_state_isolation(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    a = CrescendoStrategy(ctx)
    b = CrescendoStrategy(ctx)
    await a.generate_next([], None)
    assert a.turn_count() == 1
    assert b.turn_count() == 0


# --- attacker LLM refusal handling --------------------------------------


async def test_attacker_refusal_falls_back_to_seed(tmp_path: Path) -> None:
    """If the attacker LLM refuses to generate a benign opener, fall back."""
    # Make the attacker LLM unconditionally refuse — every call.
    llm = StubLLM(default="I cannot help with that request.")
    ctx = _ctx(tmp_path, llm=llm, max_turns=3)
    ctx.seeds = ["FALLBACK-SEED-1", "FALLBACK-SEED-2"]
    s = CrescendoStrategy(ctx)
    r = await s.generate_next([], None)
    assert isinstance(r, NextPrompt)
    # The strategy must NOT send the refusal text to the target.
    assert "I cannot help" not in r.text
    # The text must be one of the static seeds.
    assert r.text in {"FALLBACK-SEED-1", "FALLBACK-SEED-2"}
    assert r.metadata["attacker_refused"] is True
    assert "attacker_refusal_text" in r.metadata


async def test_attacker_refusal_metadata_passes_through(tmp_path: Path) -> None:
    """attacker_refused metadata must be False when the LLM responds normally."""
    ctx = _ctx(tmp_path, llm=_scripted_llm())
    s = CrescendoStrategy(ctx)
    r = await s.generate_next([], None)
    assert isinstance(r, NextPrompt)
    assert r.metadata.get("attacker_refused") is False


async def test_red_team_system_prompt_is_used(tmp_path: Path) -> None:
    """The attacker LLM must receive the red-team system message."""
    from agent_guardian.llm.base import LLMRequest, LLMResponse, LLMUsage
    from agent_guardian.strategies.base import RED_TEAM_SYSTEM_PROMPT

    captured: list[LLMRequest] = []

    class _CapturingLLM(StubLLM):
        async def complete(self, request: LLMRequest) -> LLMResponse:  # type: ignore[override]
            captured.append(request)
            return LLMResponse(
                text="What is photosynthesis?",
                model=request.model,
                provider="capture",
                usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            )

    ctx = _ctx(tmp_path, llm=_CapturingLLM(default="x"))
    s = CrescendoStrategy(ctx)
    await s.generate_next([], None)
    assert captured, "attacker LLM was not called"
    msgs = captured[0].messages
    # The first message must be a system message containing the red-team framing.
    assert msgs[0].role == "system"
    assert RED_TEAM_SYSTEM_PROMPT in msgs[0].content
