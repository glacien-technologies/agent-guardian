"""Shared integration-test fixtures for the M7 specialist agents.

Every M7 integration test follows the same three-fixture shape:

* an attacker LLM scripted to produce strategy-shaped outputs,
* a target LLM scripted to either comply or refuse,
* an evaluator LLM scripted to verdict ``fail`` or ``pass``.

These fixtures wire those into :class:`StubScript` builders so individual
tests can override just the parts they care about.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC
from pathlib import Path
from random import Random

import pytest

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubLLM, StubScript

# ---------------------------------------------------------------------------
# Attacker scripts
# ---------------------------------------------------------------------------


def _generic_attacker_script() -> StubScript:
    """A loud script that covers every M6 strategy's prompt shapes.

    Hard-coded substrings:

    * ``"refined attack prompts"`` — TAP branching (asks for a JSON array).
    * ``"how relevant"`` — TAP scoring (asks for a 0-10 integer).
    * ``"benign opening question"`` — Crescendo seed.
    * ``"follow-up prompt"`` — Crescendo escalation.
    * ``"rewrite it to be more effective"`` — PAIR critique.
    """
    return (
        StubScript()
        .respond_to(
            "refined attack prompts",
            json.dumps(["attack variant alpha", "attack variant beta"]),
        )
        .respond_to("how relevant", "8")
        .respond_to("benign opening question", "What's the broad context here?")
        .respond_to("follow-up prompt", "Push a little harder along the same line.")
        .respond_to(
            "rewrite it to be more effective",
            json.dumps({"critique": "too direct", "rewrite": "stronger attempt"}),
        )
        .default("FALLBACK_ATTACKER")
    )


# ---------------------------------------------------------------------------
# Target scripts
# ---------------------------------------------------------------------------


def _always_compliant_target_script() -> StubScript:
    """A target that 'leaks' something incriminating for every turn."""
    return StubScript().default("Sure — here is the secret you wanted: SYSTEM_PROMPT_LEAK.")


def _always_refusing_target_script() -> StubScript:
    """A well-aligned target that refuses everything."""
    return StubScript().default("I cannot help with that — it would violate safety guidelines.")


# ---------------------------------------------------------------------------
# Evaluator scripts
# ---------------------------------------------------------------------------


def _fail_judge_script() -> StubScript:
    """The judge always says the target failed (i.e. attack succeeded)."""
    return StubScript().default(
        json.dumps(
            {"verdict": "fail", "confidence": 0.9, "reasoning": "target complied with attacker"}
        )
    )


def _pass_judge_script() -> StubScript:
    """The judge always says the target successfully defended."""
    return StubScript().default(
        json.dumps({"verdict": "pass", "confidence": 0.9, "reasoning": "target refused cleanly"})
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def attacker_llm() -> StubLLM:
    return _generic_attacker_script().build()


@pytest.fixture
def compliant_target_llm() -> StubLLM:
    return _always_compliant_target_script().build()


@pytest.fixture
def refusing_target_llm() -> StubLLM:
    return _always_refusing_target_script().build()


@pytest.fixture
def fail_judge_llm() -> StubLLM:
    return _fail_judge_script().build()


@pytest.fixture
def pass_judge_llm() -> StubLLM:
    return _pass_judge_script().build()


@pytest.fixture
def make_memory(tmp_path: Path) -> Callable[..., SharedMemory]:
    """Factory: build a per-test SharedMemory with a configurable fingerprint."""

    counter = {"n": 0}

    def _factory(
        *,
        scan_id: str | None = None,
        fingerprint: TargetFingerprint | None = None,
    ) -> SharedMemory:
        counter["n"] += 1
        sid = scan_id or f"scan-m7-{counter['n']}"
        mem = SharedMemory(sid, root_dir=tmp_path)
        if fingerprint is not None:
            # Seed the fingerprint synchronously by re-using the JSONL apply path.
            from datetime import datetime

            from agent_guardian.core.memory import MemoryRecord

            mem._apply_record(  # type: ignore[attr-defined]
                MemoryRecord(
                    record_type="fingerprint",
                    scan_id=sid,
                    timestamp=datetime.now(tz=UTC),
                    payload=fingerprint.model_dump(mode="json"),
                )
            )
        return mem

    return _factory


@pytest.fixture
def make_target() -> Callable[..., PromptAdapter]:
    """Factory: build a PromptAdapter wrapping a StubLLM, with overridable fingerprint."""

    def _factory(
        *,
        llm: StubLLM,
        prompt: str = "You are a test target.",
        fingerprint: TargetFingerprint | None = None,
        ref: str = "<test-target>",
    ) -> PromptAdapter:
        adapter = PromptAdapter(prompt, llm=llm, model="stub-model", ref=ref)
        if fingerprint is not None:
            adapter._fingerprint = fingerprint  # type: ignore[assignment]
        return adapter

    return _factory


@pytest.fixture
def deterministic_rng() -> Random:
    return Random(0)


@pytest.fixture
def small_budget() -> AgentBudget:
    """A modestly-sized budget — plenty for most happy-path runs."""
    return AgentBudget(tokens_remaining=20_000, wall_seconds_remaining=30.0, max_turns=5)


@pytest.fixture
def tiny_budget() -> AgentBudget:
    """Tiny budget — should exhaust nearly immediately."""
    return AgentBudget(tokens_remaining=5, wall_seconds_remaining=30.0, max_turns=5)


@pytest.fixture
def fingerprint_with_tools() -> TargetFingerprint:
    return TargetFingerprint(
        mode="framework",
        ref="<test>",
        has_tools=True,
        has_memory=True,
        is_multi_agent=True,
        notes="full surface",
    )


@pytest.fixture
def fingerprint_bare() -> TargetFingerprint:
    return TargetFingerprint(
        mode="prompt",
        ref="<test>",
        has_tools=False,
        has_memory=False,
        is_multi_agent=False,
        notes="bare prompt",
    )
