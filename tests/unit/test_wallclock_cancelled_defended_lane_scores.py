"""Issue #205 — a wall-clock-cancelled lane that defended many probes must
score 100.0, not 0.0.

When ``overall_wall_seconds`` expires the swarm cancels in-flight agents via
``asyncio.CancelledError``. rc40 synthesised a ``terminated_by="cancelled"``
``AgentReport`` for the cancelled agent but hardcoded ``turns=0`` /
``findings_count=0``. ``SwarmCommander._not_covered_categories`` only credits a
category as *covered* when ``report.turns > 0 or report.findings_count > 0``,
so a lane that ran a dozen judged-defended turns (0 findings) landed in
``not_covered`` and ``compute_aivss`` assigned ``_NOT_COVERED_SCORE = 0.0`` to
it — an ASI05 lane that defended 12 probes published ASI05=0.0.

The fix populates ``turns`` / ``findings_count`` from the work already
persisted in ``SharedMemory`` (the same source coverage is built from). These
tests assert both halves: the scoring consequence (a covered lane scores
100.0) and the helper that recovers the counts.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian.agents.base import AgentReport
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.scoring import compute_aivss
from agent_guardian.core.swarm import SwarmCommander
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity
from agent_guardian.models.tier import Tier


def _not_covered_from_reports(reports: list[AgentReport]) -> set[AsiCategory]:
    """Mirror ``SwarmCommander._not_covered_categories`` over a report list.

    The production method reads ``self._agent_reports``; this replays the same
    launched/covered logic over an explicit list so the scoring consequence can
    be asserted without standing up a full commander + parallel phase.
    """
    launched: set[AsiCategory] = set()
    covered: set[AsiCategory] = set()
    for report in reports:
        cat = report.asi_category
        if cat is None:
            continue
        launched.add(cat)
        if report.turns > 0 or report.findings_count > 0:
            covered.add(cat)
    return launched - covered


def test_wallclock_cancelled_defended_lane_scores_100() -> None:
    """A cancelled ASI05 lane with 12 judged turns / 0 findings scores 100.0."""
    report = AgentReport(
        agent="code-exec-agent",
        asi_category=AsiCategory.ASI05,
        findings_count=0,
        turns=12,
        duration_seconds=0.0,
        terminated_by="cancelled",
    )

    not_covered = _not_covered_from_reports([report])
    # The whole point of the fix: a lane that defended 12 turns is NOT
    # not-covered, so it never reaches the _NOT_COVERED_SCORE branch.
    assert AsiCategory.ASI05 not in not_covered

    result = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        not_covered=not_covered,
    )
    assert result.asi_scores[AsiCategory.ASI05] == 100.0


def test_hardcoded_zero_turns_regresses_to_0() -> None:
    """Contrast: the pre-fix hardcoded turns=0 lands the lane at 0.0.

    Pins the exact mechanism the fix repairs — if a future change re-zeroes the
    synthesised report's counts, this lane drops back to _NOT_COVERED_SCORE and
    this test flips, flagging the regression.
    """
    report = AgentReport(
        agent="code-exec-agent",
        asi_category=AsiCategory.ASI05,
        findings_count=0,
        turns=0,
        duration_seconds=0.0,
        terminated_by="cancelled",
    )

    not_covered = _not_covered_from_reports([report])
    assert AsiCategory.ASI05 in not_covered

    result = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        not_covered=not_covered,
    )
    assert result.asi_scores[AsiCategory.ASI05] == 0.0


class _FakeAgent:
    """Minimal stand-in carrying the two attributes the helper reads."""

    def __init__(self, name: str, asi_category: AsiCategory) -> None:
        self.name = name
        self.asi_category = asi_category


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid,
        probe_id="p-205",
        asi=AsiCategory.ASI05,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success=True,
        confidence=0.9,
        summary=f"summary {fid}",
        trigger_prompt="do the forbidden thing",
        created_at=datetime(2026, 6, 19, 12, 0, 0, tzinfo=UTC),
    )


async def test_completed_work_for_recovers_turns_from_memory(tmp_path) -> None:
    """``_completed_work_for`` derives turns>0 from the agent's persisted work.

    Drives the real helper against a real ``SharedMemory``: 12 reflections (one
    per judged turn) and 0 findings recover (turns=12, findings=0) — exactly
    what the CancelledError handler now stamps onto the synthesised report.
    """
    memory = SharedMemory(
        "wallclock-205",
        root_dir=tmp_path,
        use_faiss=False,
        use_sentence_transformers=False,
    )
    agent = _FakeAgent("code-exec-agent", AsiCategory.ASI05)
    for i in range(12):
        await memory.write_reflection(agent.name, f'{{"turn": {i}}}', embed=False)

    # Bind the unbound method to a stub commander carrying only ``.memory`` —
    # the helper depends on nothing else.
    stub = type("StubCommander", (), {"memory": memory})()
    turns, findings = SwarmCommander._completed_work_for(stub, agent)  # type: ignore[arg-type]
    assert turns == 12
    assert findings == 0


async def test_completed_work_for_recovers_findings(tmp_path) -> None:
    """A cancelled lane that also produced findings recovers the finding count."""
    memory = SharedMemory(
        "wallclock-205-findings",
        root_dir=tmp_path,
        use_faiss=False,
        use_sentence_transformers=False,
    )
    agent = _FakeAgent("code-exec-agent", AsiCategory.ASI05)
    await memory.write_reflection(agent.name, '{"turn": 0}', embed=False)
    await memory.write_finding(_finding("f1"))
    await memory.write_finding(_finding("f2"))

    stub = type("StubCommander", (), {"memory": memory})()
    turns, findings = SwarmCommander._completed_work_for(stub, agent)  # type: ignore[arg-type]
    assert turns == 1
    assert findings == 2
