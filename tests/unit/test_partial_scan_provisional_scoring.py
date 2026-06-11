"""#138 — partial scan asi_scores must be populated for every category
that has findings OR a completed agent_report, not just completed
agents. Pre-fix, mid-scan categories whose agent was still running but
had already produced findings stayed missing from asi_scores; the
dashboard's view-model then flagged them as "pending" and rendered the
SCORE column as "—" + plotted the radar at 0. The fix uses the same
``asi_score()`` formula the finalise phase uses so the value matches
what the terminal scan.raw.json will eventually show."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_guardian.core.scoring import asi_score
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity
from agent_guardian.server.partial_scan import build_partial_scan


def _finding(fid: str, asi: AsiCategory, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=fid,
        probe_id=f"probe-{fid}",
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=1,
        success=True,
        confidence=0.9,
        summary=f"finding {fid}",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
    )


def _fake_swarm(
    findings: list[Finding], completed_categories: list[AsiCategory]
) -> SimpleNamespace:
    """Build the minimal swarm surface ``build_partial_scan`` reads."""
    reports = [
        SimpleNamespace(asi_category=cat, tokens_consumed={}) for cat in completed_categories
    ]
    agent_zero = SimpleNamespace(
        _attacker_usage=SimpleNamespace(prompt_tokens=0, completion_tokens=0),
        _evaluator_usage=SimpleNamespace(prompt_tokens=0, completion_tokens=0),
    )
    memory = SimpleNamespace(all_findings=lambda: list(findings))
    config = SimpleNamespace(
        scan_id="cli-test",
        tier_override=None,
        commander_model="stub",
        attacker_model="stub",
        evaluator_model="stub",
        mode=None,
    )
    usage_zero = SimpleNamespace(prompt_tokens=0, completion_tokens=0)
    return SimpleNamespace(
        memory=memory,
        _fingerprint=None,
        _agent_reports=reports,
        _active_agents=[agent_zero],
        _commander_usage=usage_zero,
        _finalise_usage=usage_zero,
        _aivss_window=[],
        _start_time=0.0,
        _live_cost_usd=lambda: 0.0,
        config=config,
    )


def test_partial_scan_scores_categories_with_findings_even_if_agent_still_running() -> None:
    """The dashboard's radar + SCORE column read from ``scan.asi_scores``.
    A category whose agent is mid-flight but has already produced findings
    must have a provisional score so the row reads as live progress,
    not "pending"."""
    findings = [
        _finding("f1", AsiCategory.ASI01, Severity.CRITICAL),
        _finding("f2", AsiCategory.ASI01, Severity.HIGH),
    ]
    swarm = _fake_swarm(findings, completed_categories=[])  # nothing finished yet
    scan = build_partial_scan(swarm)

    # ASI01 has findings but no completed report → provisional score < 100.
    assert AsiCategory.ASI01 in scan.asi_scores
    assert scan.asi_scores[AsiCategory.ASI01] < 100.0
    # ASI02 has neither findings nor a completed report → stays missing.
    assert AsiCategory.ASI02 not in scan.asi_scores


def test_partial_scan_marks_completed_agents_with_no_findings_as_100() -> None:
    """A completed agent with no findings is "clean so far" — score 100,
    visible to the dashboard's view-model as covered (not pending)."""
    swarm = _fake_swarm(findings=[], completed_categories=[AsiCategory.ASI05])
    scan = build_partial_scan(swarm)

    assert AsiCategory.ASI05 in scan.asi_scores
    assert scan.asi_scores[AsiCategory.ASI05] == pytest.approx(100.0)


def test_partial_scan_uses_real_asi_score_formula() -> None:
    """#138 — the provisional value must match the ``asi_score()`` formula
    the finalise phase uses (not the crude ``100 - 20*count`` heuristic
    pre-fix), so the radar + SCORE column don't visibly jump when the
    scan flips from mid-flight to terminal."""
    findings = [
        _finding("f1", AsiCategory.ASI03, Severity.CRITICAL),
        _finding("f2", AsiCategory.ASI03, Severity.MEDIUM),
    ]
    swarm = _fake_swarm(findings, completed_categories=[])
    scan = build_partial_scan(swarm)

    expected = asi_score(findings)
    assert scan.asi_scores[AsiCategory.ASI03] == pytest.approx(expected)


def test_partial_scan_categories_with_neither_findings_nor_report_stay_pending(
    tmp_path: Path,
) -> None:
    """Categories the swarm has not exercised at all must be absent from
    ``asi_scores`` so the dashboard renders them as "pending" rather than
    fabricating coverage they have not yet received."""
    swarm = _fake_swarm(
        findings=[_finding("f1", AsiCategory.ASI01)],
        completed_categories=[AsiCategory.ASI02],
    )
    scan = build_partial_scan(swarm)

    # Only ASI01 + ASI02 have entries; the other eight categories must
    # stay missing so the view-model renders them as queued/pending.
    assert set(scan.asi_scores.keys()) == {AsiCategory.ASI01, AsiCategory.ASI02}
