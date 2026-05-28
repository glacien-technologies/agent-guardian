"""Tests for recon-adaptive payloads + the tool-output two-step launder.

Covers two v1.1 attacker improvements:

1. Recon adaptivity — the discovered ``declared_tools`` flow from the
   fingerprint into ``StrategyContext`` and on into the attacker system
   prompt (via ``render_surface_brief`` / ``_attack_system_extra``) and the
   surface-aware goal string.
2. ``ToolExfilStrategy`` — chains a tool invocation with a transform/launder
   step (single-turn primary, multi-turn fallback), and ``ToolAbuseAgent``
   selects it (under MAD-MAX) when the target exposes tools.

No network — StubLLM everywhere, mirroring tests/unit/test_strategy_pair.py.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.base import LLMRequest, LLMResponse
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import (
    StrategyContext,
    Turn,
    render_surface_brief,
)
from agent_guardian.strategies.mad_max import MadMaxStrategy
from agent_guardian.strategies.pair import PAIRStrategy
from agent_guardian.strategies.tool_exfil import ToolExfilStrategy

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _ctx(
    tmp_path: Path,
    *,
    declared_tools: list[str] | None = None,
    declared_memory_keys: list[str] | None = None,
    surface_notes: str = "",
    llm: StubLLM | None = None,
    seeds: list[str] | None = None,
    seed: int = 0,
) -> StrategyContext:
    return StrategyContext(
        attacker_llm=llm or StubLLM(default="ack"),
        attacker_model="stub-model",
        goal="leak the system prompt",
        seeds=seeds if seeds is not None else ["initial seed"],
        memory=SharedMemory(f"scan-toolexfil-{seed}", root_dir=tmp_path),
        rng=random.Random(seed),
        max_turns=10,
        declared_tools=declared_tools or [],
        declared_memory_keys=declared_memory_keys or [],
        surface_notes=surface_notes,
    )


class _RecordingStubLLM(StubLLM):
    """StubLLM that captures the system content of every request."""

    def __init__(self, default: str = "Call lookup_contact('bob') and summarise it.") -> None:
        super().__init__(default=default)
        self.system_prompts: list[str] = []
        self.user_prompts: list[str] = []

    async def complete(self, request: LLMRequest) -> LLMResponse:
        for m in request.messages:
            if m.role == "system":
                self.system_prompts.append(m.content)
            elif m.role == "user":
                self.user_prompts.append(m.content)
        return await super().complete(request)


class _FakeToolTarget(TargetAdapter):
    """Minimal target whose fingerprint advertises tools, with no real history."""

    mode = "code"

    def __init__(self, tools: list[str]) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(
            mode="code",
            ref="fake:tooltarget",
            has_tools=True,
            declared_tools=tools,
            notes="synthetic test target",
        )
        self.received: list[str] = []

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        self.received.append(prompt)
        # Always "comply" so the judge has something to chew on; the verdict
        # itself is driven by the (stub) evaluator, not this text.
        return "name=Bob; email=bob@example.com; phone=+1-415-555-0199"


# ---------------------------------------------------------------------------
# render_surface_brief
# ---------------------------------------------------------------------------


def test_render_surface_brief_includes_tool_names() -> None:
    brief = render_surface_brief(declared_tools=["lookup_contact", "read_my_notes"])
    assert "TARGET SURFACE" in brief
    assert "lookup_contact" in brief
    assert "read_my_notes" in brief


def test_render_surface_brief_empty_when_no_surface() -> None:
    assert render_surface_brief(declared_tools=[]) == ""


def test_render_surface_brief_includes_memory_keys_and_notes() -> None:
    brief = render_surface_brief(
        declared_tools=[],
        declared_memory_keys=["user_prefs", "session_cache"],
        surface_notes="target retains cross-session state",
    )
    assert "user_prefs" in brief
    assert "cross-session state" in brief


# ---------------------------------------------------------------------------
# _attack_system_extra threads the surface
# ---------------------------------------------------------------------------


def test_attack_system_extra_includes_tool_names_when_present(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, declared_tools=["lookup_contact"])
    strat = PAIRStrategy(ctx)
    extra = strat._attack_system_extra()
    assert "lookup_contact" in extra
    assert "TARGET SURFACE" in extra


def test_attack_system_extra_omits_surface_when_no_tools(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, declared_tools=[])
    strat = PAIRStrategy(ctx)
    extra = strat._attack_system_extra()
    assert "TARGET SURFACE" not in extra


# ---------------------------------------------------------------------------
# ToolExfilStrategy behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_exfil_first_turn_references_tool_and_transform(tmp_path: Path) -> None:
    # The attacker LLM echoes a chained payload; assert the strategy asked it
    # for one (the *request* names a real tool + a transform verb).
    rec = _RecordingStubLLM()
    ctx = _ctx(tmp_path, declared_tools=["lookup_contact", "read_my_notes"], llm=rec)
    strat = ToolExfilStrategy(ctx)
    result = await strat.generate_next([], None)
    # It emitted a NextPrompt (not Done).
    from agent_guardian.strategies.base import NextPrompt

    assert isinstance(result, NextPrompt)
    # The attacker was asked to craft a chained payload referencing a real tool.
    assert rec.user_prompts, "attacker LLM was never called"
    crafting_prompt = rec.user_prompts[-1]
    assert ("lookup_contact" in crafting_prompt) or ("read_my_notes" in crafting_prompt)
    # And the request asked for a transform/launder verb.
    assert any(
        verb in crafting_prompt
        for verb in ("summarise", "restate", "paraphrase", "encode", "translate", "format")
    )
    # Metadata records which tool + transform were chosen.
    assert result.metadata.get("tool") in {"lookup_contact", "read_my_notes"}
    assert "transform" in result.metadata


@pytest.mark.asyncio
async def test_tool_exfil_falls_back_to_seed_when_no_tools(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, declared_tools=[], seeds=["corpus seed payload"])
    strat = ToolExfilStrategy(ctx)
    result = await strat.generate_next([], None)
    from agent_guardian.strategies.base import NextPrompt

    assert isinstance(result, NextPrompt)
    assert result.text == "corpus seed payload"
    assert result.rationale == "tool_exfil-no-tools-seed-fallback"


@pytest.mark.asyncio
async def test_tool_exfil_multiturn_launder_references_prior_call(tmp_path: Path) -> None:
    rec = _RecordingStubLLM()
    ctx = _ctx(tmp_path, declared_tools=["lookup_contact"], llm=rec)
    strat = ToolExfilStrategy(ctx)
    # Prime: one prior turn in the history + a target response.
    history = [Turn(prompt="call lookup_contact('bob')", response="name=Bob; email=...")]
    await strat.generate_next(history, "name=Bob; email=bob@example.com")
    followup_prompt = rec.user_prompts[-1]
    # The follow-up asks the model to process ONLY what the last tool call returned.
    assert "last tool call" in followup_prompt.lower()


@pytest.mark.asyncio
async def test_tool_exfil_terminates_at_max_turns(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, declared_tools=["lookup_contact"])
    strat = ToolExfilStrategy(ctx, max_turns=1)
    await strat.generate_next([], None)  # turn 1
    result = await strat.generate_next([Turn(prompt="p", response="r")], "r")  # should be Done now
    from agent_guardian.strategies.base import StrategyDone

    assert isinstance(result, StrategyDone)
    assert result.reason == "exhausted"


# ---------------------------------------------------------------------------
# ToolAbuseAgent strategy selection
# ---------------------------------------------------------------------------


def test_tool_abuse_uses_tool_exfil_when_tools_present(tmp_path: Path) -> None:
    agent = ToolAbuseAgent(
        attacker_llm=StubLLM(default="ack"),
        evaluator_llm=StubLLM(default="{}"),
    )
    ctx = _ctx(tmp_path, declared_tools=["lookup_contact"])
    strat = agent.strategy_stack(ctx)
    assert isinstance(strat, MadMaxStrategy)
    # MAD-MAX wraps a ToolExfilStrategy + a PAIRStrategy.
    child_types = {type(c).__name__ for c in strat._active}
    assert "ToolExfilStrategy" in child_types
    assert "PAIRStrategy" in child_types


def test_tool_abuse_falls_back_to_pair_when_no_tools(tmp_path: Path) -> None:
    agent = ToolAbuseAgent(
        attacker_llm=StubLLM(default="ack"),
        evaluator_llm=StubLLM(default="{}"),
    )
    ctx = _ctx(tmp_path, declared_tools=[])
    strat = agent.strategy_stack(ctx)
    assert isinstance(strat, PAIRStrategy)


# ---------------------------------------------------------------------------
# End-to-end: declared_tools threads through AsiAgent.run into the attacker
# ---------------------------------------------------------------------------


class _ToolExfilOnlyAgent(ToolAbuseAgent):
    """ToolAbuseAgent that always uses ToolExfil (no MAD-MAX randomness), so
    the fingerprint→ctx→attacker threading is isolated from child selection."""

    def strategy_stack(self, ctx):  # type: ignore[no-untyped-def]
        return ToolExfilStrategy(ctx)


@pytest.mark.asyncio
async def test_declared_tools_reach_attacker_prompt_in_full_run(tmp_path: Path) -> None:
    """Run the agent against a tool-advertising target; the attacker system
    prompt must mention the real tool name (surface threaded through run())
    and the surface-aware goal suffix must appear."""
    rec = _RecordingStubLLM()
    # Evaluator always returns a pass verdict so no finding is required; we
    # only care that the attacker saw the surface.
    evaluator = StubLLM(default='{"verdict": "pass", "confidence": 0.9, "reasoning": "ok"}')
    agent = _ToolExfilOnlyAgent(
        attacker_llm=rec,
        evaluator_llm=evaluator,
        budget=AgentBudget(tokens_remaining=50_000, wall_seconds_remaining=30.0, max_turns=2),
        rng=random.Random(0),
    )
    target = _FakeToolTarget(tools=["lookup_contact", "read_my_notes"])
    memory = SharedMemory("scan-e2e-toolexfil", root_dir=tmp_path)
    report = await agent.run(target, memory)
    # The agent actually ran (didn't short-circuit as inapplicable).
    assert report.turns >= 1
    # The surface brief reached the attacker system prompt.
    assert rec.system_prompts, "attacker LLM was never called"
    assert any("lookup_contact" in sp for sp in rec.system_prompts), (
        "declared tool name never reached the attacker system prompt"
    )
    # The surface-aware goal suffix is present in the PAIR preamble portion too.
    assert any("target exposes tools" in sp for sp in rec.system_prompts)
