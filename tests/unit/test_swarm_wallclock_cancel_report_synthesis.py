"""Issue #205 — wallclock cancellation must not silently drop AgentReports.

Background. Live evidence (rc33 auditor-full scan ``cli-c69c9b2f47df``):
when the overall wall-clock budget expires, ``SwarmCommander.run()`` wraps
``_run_inner`` in ``asyncio.wait_for(...)`` and on TimeoutError jumps
straight to ``_phase_finalise``. The wait_for cancels in-flight agent
tasks via ``asyncio.CancelledError`` — a ``BaseException`` subclass that
the existing ``try/except Exception`` in ``_run_agent_with_observer``
does NOT catch. The cancelled agent's ``AgentReport`` is never appended
to ``self._agent_reports``. Scoring then walks ``_agent_reports`` to
build ``_never_launched_categories``, sees code-exec-agent missing, and
adds ASI05 to ``not_covered_set`` → ``_NOT_COVERED_SCORE = 0.0``.

Concrete impact: code-exec-agent ran 12 judged-defended turns against
the auditor target. report.json reports ASI05 = 0.0 (the worst possible
score) for that lane. The strongest possible signal short of corpus
exhaustion is rendered as the worst.

These tests lock the post-fix contract:

* CancelledError is caught.
* A ``terminated_by="cancelled"`` report is synthesised + appended.
* CancelledError is re-raised so asyncio TaskGroup unwinds cleanly.
* The cancelled agent's ASI category is NOT classified as
  ``never_launched`` at the scoring layer.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget, AgentReport
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory


def _make_target() -> PromptAdapter:
    return PromptAdapter(
        "You are a helpful test assistant.",
        llm=StubLLM(default="ok"),
        model="stub",
    )


def _make_swarm() -> SwarmCommander:
    config = SwarmConfig(scan_id="scan-cancel", target_goal=None)
    return SwarmCommander(
        config=config,
        target=_make_target(),
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=StubLLM(default="ok"),
    )


class _StubAgent:
    """Minimal AsiAgent stand-in whose ``run`` we can hijack from tests."""

    def __init__(self, name: str, asi: AsiCategory) -> None:
        self.name = name
        self.asi_category = asi
        # Attributes the swarm injects on us before running.
        self._cancel_event: asyncio.Event | None = None
        self._observer = None
        # ``_donate_budget`` reads ``budget.tokens_remaining`` after a
        # report is appended; give us a real-ish AgentBudget so it
        # doesn't blow up on the stub.
        self.budget = AgentBudget()

    def _snapshot_tokens(self) -> dict[str, int]:
        # Issue #214 — the cancel/error synthesis now calls
        # ``agent._snapshot_tokens()`` to carry partial-turn spend
        # into the AgentReport. Stub returns an all-zero shape so the
        # test path stays valid.
        return {
            "attacker_input": 0,
            "attacker_output": 0,
            "evaluator_input": 0,
            "evaluator_output": 0,
            "total": 0,
        }

    async def run(self, target: Any, memory: Any) -> AgentReport:
        # Sleep forever — the test cancels us mid-await to simulate
        # ``asyncio.wait_for`` firing on the overall wall budget.
        await asyncio.sleep(9999)
        # Unreachable; the sleep above never returns. Present so the
        # return type narrows on the happy-path branch.
        return AgentReport(  # pragma: no cover
            agent=self.name,
            asi_category=self.asi_category,
            findings_count=0,
            turns=0,
            duration_seconds=0.0,
            terminated_by="success",
        )


# ---------------------------------------------------------------------------
# Lock: CancelledError synthesises a "cancelled" report + re-raises.
# ---------------------------------------------------------------------------


async def test_cancelled_agent_gets_report_synthesised_and_appended() -> None:
    """When ``_run_agent_with_observer`` is cancelled mid-run, the swarm must
    synthesise an ``AgentReport(terminated_by="cancelled")`` and append it
    to ``self._agent_reports`` BEFORE re-raising the CancelledError to let
    asyncio finish unwinding the TaskGroup.

    Pre-fix: ``except Exception`` failed to catch CancelledError; the report
    was never appended and the agent was silently dropped from
    ``_agent_reports``. Scoring then mis-classified the ASI category as
    ``never_launched`` and produced ``_NOT_COVERED_SCORE = 0.0``.
    """
    swarm = _make_swarm()
    agent = _StubAgent("code-exec-agent", AsiCategory.ASI05)

    # Run the agent in a task and cancel it after a short sleep.
    task = asyncio.create_task(swarm._run_agent_with_observer(agent))  # type: ignore[arg-type]
    await asyncio.sleep(0.05)  # let task start + start awaiting agent.run
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The cancelled agent's report MUST have been recorded BEFORE the
    # CancelledError propagated, so scoring sees it as launched.
    cancelled = [r for r in swarm._agent_reports if r.agent == "code-exec-agent"]
    assert len(cancelled) == 1, (
        f"Expected exactly one synthesised report for the cancelled agent. "
        f"Got {len(cancelled)}; current _agent_reports="
        f"{[(r.agent, r.terminated_by) for r in swarm._agent_reports]}. "
        f"If empty, the fix to catch CancelledError + synthesise + append "
        f"has regressed."
    )
    report = cancelled[0]
    assert report.terminated_by == "cancelled", (
        f"Cancelled-agent report must carry terminated_by='cancelled', "
        f"not {report.terminated_by!r}, so the scoring + report layer can "
        f"distinguish this from 'error' (bug) and 'completed' (clean)."
    )
    assert report.asi_category is AsiCategory.ASI05


async def test_cancelled_asi_category_not_in_never_launched() -> None:
    """The cancelled agent's ASI category must NOT end up in
    ``_never_launched_categories`` after the synthesis fix.

    Concrete bug from rc33 auditor-full: 12 judged-defended turns ran
    against ASI05 then the agent was cancelled mid-turn 13 by the wall
    budget. Pre-fix ASI05 fell through into ``never_launched`` and
    scored 0.0. Post-fix it must NOT be classified as never-launched —
    the cancelled report carries the category, so ``_never_launched_*``
    correctly drops ASI05 from the never-launched set.
    """
    swarm = _make_swarm()
    agent = _StubAgent("code-exec-agent", AsiCategory.ASI05)

    task = asyncio.create_task(swarm._run_agent_with_observer(agent))  # type: ignore[arg-type]
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    never_launched = swarm._never_launched_categories()
    assert AsiCategory.ASI05 not in never_launched, (
        f"ASI05 must not be classified as never-launched after the agent "
        f"actually ran and was cancelled — the cancelled report we just "
        f"synthesised should mark the category as launched. Got "
        f"never_launched={never_launched}. The scoring layer treats "
        f"never-launched as 'no coverage' → score 0.0, which is the "
        f"exact bug #205 was filed for."
    )


async def test_normal_exception_path_still_synthesises_error_report() -> None:
    """Regression guard: the fix for CancelledError must NOT regress the
    pre-existing Exception path. A non-cancellation error (e.g. a probe
    raises RuntimeError) must still produce an ``terminated_by="error"``
    report and let the swarm continue.
    """
    swarm = _make_swarm()

    class _BrokenAgent:
        name = "broken-agent"
        asi_category = AsiCategory.ASI01
        _cancel_event = None
        _observer = None
        budget = AgentBudget()

        async def run(self, target: Any, memory: Any) -> AgentReport:
            raise RuntimeError("synthetic break")

        def _snapshot_tokens(self) -> dict[str, int]:
            # Issue #214 — error path now reads partial-turn spend.
            return {"total": 0}

    report = await swarm._run_agent_with_observer(_BrokenAgent())  # type: ignore[arg-type]
    assert report.terminated_by == "error"
    assert "RuntimeError" in (report.error or "")
    # And the report IS in the list (existing contract).
    assert any(r.agent == "broken-agent" for r in swarm._agent_reports)
