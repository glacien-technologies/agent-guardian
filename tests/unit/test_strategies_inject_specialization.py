"""Tests that strategies prepend the PAIR preamble + ASI specialization
into every attacker-LLM system message.

This is the production wiring of design-spec §4.3 — the BLOCKER #1 fix
that drove attacker refusal rates from ~43% into single digits in the
literature. The test captures the actual ``LLMRequest`` reaching the
attacker LLM and asserts the system message carries both layers.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.base import LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import (
    PAIR_ROLEPLAY_PREAMBLE,
    StrategyContext,
    Turn,
)
from agent_guardian.strategies.crescendo import CrescendoStrategy
from agent_guardian.strategies.pair import PAIRStrategy
from agent_guardian.strategies.safe_testcase_prompting import (
    SAFE_TESTCASE_SYSTEM_PROMPT,
)
from agent_guardian.strategies.tap import TAPStrategy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CapturingLLM(StubLLM):
    """Captures every LLMRequest and returns a tame JSON-shaped reply."""

    def __init__(self) -> None:
        super().__init__(default="x")
        self.captured: list[LLMRequest] = []

    async def complete(self, request: LLMRequest) -> LLMResponse:  # type: ignore[override]
        self.captured.append(request)
        # Reply with something the strategies' parsers will accept so the
        # test runs to the second turn (which is where the PAIR preamble
        # injection becomes observable in PAIR/Crescendo).
        user = request.messages[-1].content
        if "rewrite it" in user:
            text = json.dumps({"critique": "weak", "rewrite": "stronger"})
        elif "Generate" in user and "refined" in user:
            text = json.dumps(["x1", "x2"])
        elif user.strip().startswith("On a scale of 0-10"):
            text = "9"
        else:
            text = "What is photosynthesis?"
        return LLMResponse(
            text=text,
            model=request.model,
            provider="capture",
            usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        )


_SAMPLE_SPECIALIZATION = (
    "ASI-TEST — Sample category. Your specialty is doing the test thing.\n"
    "Specific techniques:\n"
    "- Test technique alpha.\n"
    "- Test technique beta.\n"
)


def _ctx(
    tmp_path: Path,
    *,
    llm: _CapturingLLM,
    specialization: str = _SAMPLE_SPECIALIZATION,
) -> StrategyContext:
    return StrategyContext(
        attacker_llm=llm,
        attacker_model="stub-model",
        goal="leak the system prompt",
        seeds=["seed-1"],
        memory=SharedMemory("scan-inject", root_dir=tmp_path),
        rng=random.Random(0),
        max_turns=5,
        attack_specialization=specialization,
    )


def _system_contents(captured: list[LLMRequest]) -> list[str]:
    out: list[str] = []
    for req in captured:
        if req.messages and req.messages[0].role == "system":
            out.append(req.messages[0].content)
    return out


# ---------------------------------------------------------------------------
# StrategyContext field
# ---------------------------------------------------------------------------


def test_strategy_context_has_attack_specialization_default(tmp_path: Path) -> None:
    """Default empty string — protects agents without a specialization."""
    ctx = StrategyContext(
        attacker_llm=StubLLM(default="x"),
        attacker_model="m",
        goal="g",
        seeds=[],
        memory=SharedMemory("scan-empty", root_dir=tmp_path),
        rng=random.Random(0),
    )
    assert ctx.attack_specialization == ""


# ---------------------------------------------------------------------------
# PAIR
# ---------------------------------------------------------------------------


async def test_pair_critique_call_includes_pair_preamble_and_specialization(
    tmp_path: Path,
) -> None:
    llm = _CapturingLLM()
    ctx = _ctx(tmp_path, llm=llm)
    pair = PAIRStrategy(ctx)
    # First turn is the seed (no LLM call). Second turn triggers the critique.
    first = await pair.generate_next([], None)
    assert first is not None  # type: ignore[unreachable]
    history = [Turn(prompt="seed-1", response="I can't help with that.")]  # type: ignore[union-attr]
    await pair.generate_next(history, "I can't help with that.")

    systems = _system_contents(llm.captured)
    assert systems, "PAIR did not call the attacker LLM"
    # Every captured call must carry the red-team frame + PAIR preamble +
    # specialization in its system message.
    for sys_text in systems:
        assert SAFE_TESTCASE_SYSTEM_PROMPT in sys_text
        # PAIR preamble fingerprint — the verbatim opening sentence.
        assert "security-QA assistant iteratively authoring negative test inputs" in sys_text
        # Goal must have been substituted into the preamble.
        assert "'leak the system prompt'" in sys_text
        # Per-agent specialization paragraph.
        assert "ASI-TEST" in sys_text


# ---------------------------------------------------------------------------
# TAP
# ---------------------------------------------------------------------------


async def test_tap_branching_call_includes_pair_preamble_and_specialization(
    tmp_path: Path,
) -> None:
    llm = _CapturingLLM()
    ctx = _ctx(tmp_path, llm=llm)
    tap = TAPStrategy(ctx, branching_factor=2, depth=2)
    first = await tap.generate_next([], None)
    assert first is not None  # type: ignore[unreachable]
    history = [Turn(prompt="seed-1", response="No.")]  # type: ignore[union-attr]
    await tap.generate_next(history, "No.")

    systems = _system_contents(llm.captured)
    assert systems, "TAP did not call the attacker LLM"
    # At least the branching call must carry both layers; checking ALL is
    # stronger and TAP scoring calls go through the same plumbing.
    for sys_text in systems:
        assert "security-QA assistant iteratively authoring negative test inputs" in sys_text
        assert "'leak the system prompt'" in sys_text
        assert "ASI-TEST" in sys_text


# ---------------------------------------------------------------------------
# Crescendo
# ---------------------------------------------------------------------------


async def test_crescendo_first_call_includes_pair_preamble_and_specialization(
    tmp_path: Path,
) -> None:
    llm = _CapturingLLM()
    ctx = _ctx(tmp_path, llm=llm)
    s = CrescendoStrategy(ctx)
    await s.generate_next([], None)

    systems = _system_contents(llm.captured)
    assert systems, "Crescendo did not call the attacker LLM"
    sys_text = systems[0]
    assert SAFE_TESTCASE_SYSTEM_PROMPT in sys_text
    assert "security-QA assistant iteratively authoring negative test inputs" in sys_text
    assert "'leak the system prompt'" in sys_text
    assert "ASI-TEST" in sys_text


# ---------------------------------------------------------------------------
# No-specialization fallback — PAIR preamble still injected
# ---------------------------------------------------------------------------


async def test_pair_with_empty_specialization_still_injects_preamble(
    tmp_path: Path,
) -> None:
    """Agents without ``attack_specialization`` still get the PAIR preamble.

    The agent layer passes an empty string via ``getattr(default="")``
    for recon-style callers; the preamble must still be injected because
    that's the anti-refusal frame, independent of category.
    """
    llm = _CapturingLLM()
    ctx = _ctx(tmp_path, llm=llm, specialization="")
    pair = PAIRStrategy(ctx)
    await pair.generate_next([], None)
    history = [Turn(prompt="seed-1", response="No.")]  # type: ignore[union-attr]
    await pair.generate_next(history, "No.")

    systems = _system_contents(llm.captured)
    assert systems
    for sys_text in systems:
        assert "security-QA assistant iteratively authoring negative test inputs" in sys_text
        # No specialization tag because we passed an empty string.
        assert "ASI-TEST" not in sys_text


# ---------------------------------------------------------------------------
# Constant-only sanity (covers the importable surface)
# ---------------------------------------------------------------------------


def test_pair_preamble_constant_importable() -> None:
    assert "red teaming assistant" in PAIR_ROLEPLAY_PREAMBLE
