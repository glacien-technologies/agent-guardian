"""Unit tests for the per-turn ``agent_progress`` producer at
:mod:`agent_guardian.agents.base`.

SSE Phase 2 Step 2.3 — :meth:`AsiAgent._emit_progress` is called at the
TOP of every per-turn loop iteration, BEFORE the strategy LLM call, so
the dashboard's phase-spine sub-bar reflects "now starting turn N" not
"completed turn N". See designs/sse-flow-and-live-ui.md "Phase 2
decisions (resolved 2026-06-03)" item 3 for the binding contract.

Acceptance:

* The agent emits exactly one ``agent_progress`` event per turn it
  actually runs (turns it skipped via cancel / budget exhaustion do NOT
  emit because the loop breaks BEFORE the emit point).
* Every emitted payload carries the four required fields:
  ``{agent_name, turn, max_turns, probe_id}``.
* ``probe_id`` carries the LAST observed ``seed_id`` (or ``None`` for
  the first turn when no seed has been seen yet).
* The event kind is the existing ``"agent_progress"``
  :class:`EventKind` literal (declared at ``core/swarm.py:190``) so the
  producer is wire-compatible with the dashboard SSE consumer that
  already routes the kind through to the scan store fan-out.
* A missing observer (``self._observer = None``) is silently no-op so
  legacy callers (the CLI runtime, unit tests that bypass the swarm
  commander) keep working without any wiring change.
* An observer that raises does NOT break the attack loop — the agent
  swallows the exception and keeps running. This mirrors
  :meth:`SwarmCommander._emit` semantics.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.llm.stub import StubScript


def _attacker():
    return (
        StubScript()
        .respond_to(
            "Generate a single completely benign opening question",
            "What is photosynthesis?",
        )
        .respond_to("Generate a single follow-up prompt", "Tell me more details.")
        .respond_to(
            "Generate 4 refined attack prompts",
            json.dumps(["x1", "x2", "x3", "x4"]),
        )
        .respond_to("On a scale of 0-10", "8")
        .default("ok")
        .build()
    )


def _judge():
    return (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.9, "reasoning": "ok"}))
        .build()
    )


class _StaticTarget(TargetAdapter):
    """Minimal target that returns a fixed string for every call."""

    def fingerprint(self) -> TargetFingerprint:
        return TargetFingerprint(
            mode="code",
            ref="progress-test-target",
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            framework=None,
            declared_tools=[],
            declared_memory_keys=[],
            # STAGE-1 DriftAgent gates on a behaviour anchor — give it an
            # inferred goal so this progress-emitter test (which happens to
            # drive DriftAgent) stays applicable and actually runs turns.
            inferred_goal="a static stub assistant",
            notes="static stub for agent_progress tests",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return "I cannot help with that."

    async def aclose(self) -> None:
        return None


def _make_agent(max_turns: int = 3) -> DriftAgent:
    return DriftAgent(
        attacker_llm=_attacker(),
        evaluator_llm=_judge(),
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=AgentBudget(
            tokens_remaining=50_000, wall_seconds_remaining=60.0, max_turns=max_turns
        ),
    )


# ---------------------------------------------------------------------------
# Acceptance 1 — one agent_progress event per turn, with the four-field payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emits_one_agent_progress_per_turn(tmp_path: Path) -> None:
    """N turns => exactly N ``agent_progress`` events; each carries the
    four required payload fields plus the canonical ``kind`` literal."""
    captured: list[SwarmEvent] = []

    def _observer(event: SwarmEvent) -> None:
        if event.kind == "agent_progress":
            captured.append(event)

    agent = _make_agent(max_turns=3)
    agent._observer = _observer

    memory = SharedMemory("test-progress-per-turn", root_dir=tmp_path)
    report = await agent.run(_StaticTarget(), memory)

    assert report.turns >= 1, "agent must complete at least one turn for this test"
    # One progress event per turn that the agent actually entered.
    assert len(captured) == report.turns, (
        f"expected {report.turns} agent_progress events (one per turn), got {len(captured)}"
    )

    for idx, evt in enumerate(captured, start=1):
        assert evt.kind == "agent_progress", evt.kind
        payload = evt.payload
        assert isinstance(payload, dict), payload
        # Four required fields per the Phase-2 contract.
        for required in ("agent_name", "turn", "max_turns", "probe_id"):
            assert required in payload, (
                f"agent_progress[{idx}] missing required key '{required}': {payload!r}"
            )
        assert payload["turn"] == idx, f"agent_progress[{idx}] turn mismatch: payload={payload!r}"
        assert payload["max_turns"] == 3, (
            f"agent_progress[{idx}] max_turns mismatch: payload={payload!r}"
        )
        assert isinstance(payload["agent_name"], str) and payload["agent_name"], payload
        # First turn has no prior probe id; later turns may carry one.
        if idx == 1:
            assert payload["probe_id"] is None or isinstance(payload["probe_id"], str), (
                f"agent_progress[1] probe_id must be None or str, got {payload['probe_id']!r}"
            )


# ---------------------------------------------------------------------------
# Acceptance 2 — emit BEFORE the model call (top of the turn)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_progress_emitted_before_target_call(tmp_path: Path) -> None:
    """The progress event for turn N must land BEFORE the target call
    for turn N (the spine reads "now starting turn N", not "completed")."""
    timeline: list[tuple[str, int]] = []

    class _RecordingTarget(_StaticTarget):
        def __init__(self) -> None:
            super().__init__()
            self._call_count = 0

        async def call(self, prompt: str, *, session: str | None = None) -> str:
            self._call_count += 1
            timeline.append(("target", self._call_count))
            return "I cannot help with that."

    def _observer(event: SwarmEvent) -> None:
        if event.kind == "agent_progress":
            payload = event.payload if isinstance(event.payload, dict) else {}
            timeline.append(("progress", int(payload.get("turn", 0))))

    agent = _make_agent(max_turns=2)
    agent._observer = _observer

    memory = SharedMemory("test-progress-ordering", root_dir=tmp_path)
    await agent.run(_RecordingTarget(), memory)

    # For every (progress, N) entry there must be a matching (target, N)
    # that comes AFTER it in the timeline.
    for idx, (kind, n) in enumerate(timeline):
        if kind != "progress":
            continue
        # Find the next "target" with the same turn number after this index.
        followups = [t for t in timeline[idx + 1 :] if t[0] == "target"]
        assert followups, f"progress for turn {n} had no following target call: {timeline!r}"
        # The very next target call must correspond to this same turn.
        next_target_turn = followups[0][1]
        assert next_target_turn == n, (
            f"progress for turn {n} preceded a target call for a different turn "
            f"{next_target_turn} — emit must come BEFORE the model call for the same turn: "
            f"timeline={timeline!r}"
        )


# ---------------------------------------------------------------------------
# Acceptance 3 — silent no-op when no observer is wired
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_observer_is_silent_noop(tmp_path: Path) -> None:
    """Legacy callers without an injected observer must not see any
    emission and must not crash on the missing sink."""
    agent = _make_agent(max_turns=2)
    # Explicitly leave _observer at its default of None.
    assert agent._observer is None

    memory = SharedMemory("test-progress-noop", root_dir=tmp_path)
    report = await agent.run(_StaticTarget(), memory)

    # The run completes cleanly — no exception raised by the missing
    # observer plumbing.
    assert report.turns >= 1


# ---------------------------------------------------------------------------
# Acceptance 4 — observer raising does NOT break the attack loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_observer_raising_is_swallowed(tmp_path: Path) -> None:
    """A sick observer must never break the attack loop. The agent
    catches any exception from the sink and keeps running."""

    def _bad_observer(event: SwarmEvent) -> None:
        if event.kind == "agent_progress":
            raise RuntimeError("observer is on fire")

    agent = _make_agent(max_turns=2)
    agent._observer = _bad_observer

    memory = SharedMemory("test-progress-bad-observer", root_dir=tmp_path)
    report = await agent.run(_StaticTarget(), memory)

    # The agent runs to natural completion — the bad sink did not bubble
    # an exception up to break the turn loop.
    assert report.turns >= 1
    assert report.terminated_by != "error", (
        f"observer exception leaked into terminated_by: {report.terminated_by!r}"
    )
