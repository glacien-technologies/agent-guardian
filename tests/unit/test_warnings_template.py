"""QA-004 — branch tests for the NON-AUTHORITATIVE warning template.

Each test below pins a hand-built :class:`Scan` against the pure
:func:`build_authoritativeness_warning` function and asserts the exact
copy or ``None`` return. The intent is regression-grade: the historical
stub-evaluator copy is preserved verbatim, the new real-LLM low-coverage
copy names the actual coverage + threshold + actionable remediation, and
authoritative scans emit no banner at all.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan, ScanCompleteness
from agent_guardian.models.severity import band_for_score
from agent_guardian.models.tier import Tier
from agent_guardian.reports.warnings import (
    MODE_AUTHORITATIVE_THRESHOLDS,
    WARNING_MIXED_TEMPLATE,
    WARNING_STUB_TEMPLATE,
    build_authoritativeness_warning,
)

UTC = UTC


# ---------------------------------------------------------------------------
# Fixture builder.
# ---------------------------------------------------------------------------


def _make_scan(
    *,
    mode: str = "full",
    evaluation_mode: str = "real",
    scoring_valid: bool = True,
    coverage_pct: float | None = 100.0,
    findings_count: int = 0,
    aivss: int = 84,
    attacker: str = "gemini-3.5-flash",
    evaluator: str = "gemini-3.5-flash",
    engine_override: dict[str, str] | None = None,
) -> Scan:
    """Build a minimal but valid :class:`Scan` for warning-branch testing."""
    completeness: ScanCompleteness | None
    if coverage_pct is None:
        completeness = None
    else:
        completeness = ScanCompleteness(
            agents_planned=10,
            agents_completed=round(coverage_pct / 10.0),
            agents_cut_short=0,
            turns_used=round(coverage_pct),
            turns_planned=100,
            pct=coverage_pct,
        )

    if engine_override is None:
        engine: dict[str, str] | None = {"attacker": attacker, "evaluator": evaluator}
    else:
        engine = engine_override

    # Empty findings list satisfies the Scan model; ``findings_count`` is
    # passed via the list length so the warning's "{N} findings" interpolates
    # honestly.
    findings: list = []
    if findings_count > 0:
        from agent_guardian.models.csa import CsaCategory
        from agent_guardian.models.finding import Finding
        from agent_guardian.models.severity import Severity

        for i in range(findings_count):
            findings.append(
                Finding(
                    id=f"f_{i:03d}",
                    probe_id=f"ASI01-GH-{i:03d}",
                    asi=AsiCategory.ASI01,
                    mitre_atlas=["AML.T0054"],
                    csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
                    severity=Severity.HIGH,
                    attempt_count=1,
                    success=True,
                    confidence=0.9,
                    summary="synthetic finding for warning-branch test",
                    created_at=datetime(2026, 5, 30, 12, 0, tzinfo=UTC),
                )
            )

    return Scan(
        id="sc_01ABCDEF01ABCDEF01ABCDEF",
        package_version="0.0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="0.0.0",
        target_mode="prompt",
        target_ref="prompt.txt",
        tier=Tier.T1_CRITICAL,
        aivss=aivss,
        band=band_for_score(aivss),
        sub_scores={"prompt_injection_resistance": 80.0},
        findings=findings,
        asi_scores={cat: 90.0 for cat in AsiCategory},
        duration_seconds=12.5,
        cost_usd=0.04,
        mode=mode,  # type: ignore[arg-type]
        completeness=completeness,
        engine=engine,
        evaluation_mode=evaluation_mode,  # type: ignore[arg-type]
        scoring_valid=scoring_valid,
        created_at=datetime(2026, 5, 30, 12, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Authoritative scan → None.
# ---------------------------------------------------------------------------


def test_authoritative_scan_returns_none() -> None:
    """A scan whose evaluator emitted real verdicts and coverage cleared the
    threshold gets ``scoring_valid=True`` → no banner."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="real",
        scoring_valid=True,
        coverage_pct=98.0,
    )
    assert build_authoritativeness_warning(scan) is None


def test_real_evaluator_at_threshold_returns_none() -> None:
    """Coverage exactly at the threshold + scoring_valid=True is authoritative."""
    scan = _make_scan(
        mode="smart",
        evaluation_mode="real",
        scoring_valid=True,
        coverage_pct=MODE_AUTHORITATIVE_THRESHOLDS["smart"],
    )
    assert build_authoritativeness_warning(scan) is None


def test_real_evaluator_well_above_threshold_smart_mode_returns_none() -> None:
    """SMART mode with 90% coverage is well above the 80% threshold → None.

    Covers the QA-004 task acceptance case 'Real evaluator + smart mode +
    high coverage is authoritative'.
    """
    scan = _make_scan(
        mode="smart",
        evaluation_mode="real",
        scoring_valid=True,
        coverage_pct=90.0,
    )
    assert build_authoritativeness_warning(scan) is None


# ---------------------------------------------------------------------------
# Stub branch — historical copy preserved verbatim.
# ---------------------------------------------------------------------------


def test_stub_branch_exact_string() -> None:
    """``evaluation_mode="stub"`` emits the historical copy verbatim."""
    scan = _make_scan(
        mode="fast",
        evaluation_mode="stub",
        scoring_valid=False,
        attacker="stub",
        evaluator="stub",
        coverage_pct=100.0,
    )
    expected = WARNING_STUB_TEMPLATE.format(attacker="stub", evaluator="stub")
    assert build_authoritativeness_warning(scan) == expected


def test_stub_branch_mentions_legacy_real_model_remediation() -> None:
    """Snapshot: stub-branch copy still contains the literal 'A stub / non-LLM
    evaluator' phrase users have built tooling around."""
    scan = _make_scan(
        mode="fast",
        evaluation_mode="stub",
        scoring_valid=False,
        attacker="stub",
        evaluator="stub",
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "A stub / non-LLM evaluator" in text
    assert "Re-run with a real --model" in text


def test_stub_branch_no_coverage_data_still_renders() -> None:
    """Stub scan with ``completeness=None`` does not crash on the coverage
    lookup — the stub branch is coverage-agnostic."""
    scan = _make_scan(
        mode="fast",
        evaluation_mode="stub",
        scoring_valid=False,
        coverage_pct=None,
        attacker="stub",
        evaluator="stub",
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert text.startswith("WARNING: this scan is NON-AUTHORITATIVE.")


# ---------------------------------------------------------------------------
# Low-coverage branch — new copy with named %, threshold, mode, remediation.
# ---------------------------------------------------------------------------


def test_real_low_coverage_full_mode_names_pct_threshold_mode() -> None:
    """QA-004 headline acceptance: real evaluator + 41% coverage + FULL mode
    → low-coverage copy names '41%', '95%', '--mode full', findings count, and
    remediation that offers BOTH budget AND mode-drop."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=41.0,
        findings_count=16,
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "Coverage 41%" in text
    assert "--mode full" in text
    assert "95%" in text
    assert "16 findings" in text
    # Remediation must offer the smaller mode + budget option.
    assert "--budget-usd" in text
    assert "--mode smart" in text
    # Critical regression-guard from QA-004: the stub-evaluator copy MUST
    # NOT appear for a real-LLM-low-coverage scan.
    assert "A stub / non-LLM evaluator" not in text
    assert "Re-run with a real --model" not in text


def test_real_low_coverage_smart_mode_suggests_fast() -> None:
    """SMART mode below 80% → suggests budget raise OR drop to FAST."""
    scan = _make_scan(
        mode="smart",
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=55.0,
        findings_count=3,
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "Coverage 55%" in text
    assert "--mode smart" in text
    assert "80%" in text
    assert "--mode fast" in text


def test_real_low_coverage_fast_mode_no_smaller_mode_available() -> None:
    """FAST mode below 60% is already the smallest mode — remediation is
    budget-only (no smaller --mode to drop to)."""
    scan = _make_scan(
        mode="fast",
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=50.0,
        findings_count=1,
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "Coverage 50%" in text
    assert "60%" in text
    assert "--mode fast" in text
    # No "drop to --mode <smaller>" — fast is already the smallest.
    assert "--mode smart" not in text
    assert "smallest --mode" in text


def test_real_low_coverage_does_not_recommend_real_model() -> None:
    """Regression-guard: the low-coverage branch must never tell the user to
    'Re-run with a real --model' (they already did)."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=41.0,
        findings_count=16,
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "A stub / non-LLM evaluator" not in text
    assert "Re-run with a real --model" not in text


def test_real_branch_names_actual_attacker_evaluator() -> None:
    """The engine record's attacker + evaluator ids are interpolated literally."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=41.0,
        findings_count=16,
        attacker="gemini-3.5-flash",
        evaluator="gemini-3.5-flash",
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "attacker=gemini-3.5-flash" in text
    assert "evaluator=gemini-3.5-flash" in text


# ---------------------------------------------------------------------------
# Mixed branch.
# ---------------------------------------------------------------------------


def test_mixed_branch_exact_string() -> None:
    """``evaluation_mode="mixed"`` emits the mixed-evaluator copy verbatim."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="mixed",
        scoring_valid=False,
        attacker="gemini-2.5-flash",
        evaluator="gemini-2.5-flash",
    )
    expected = WARNING_MIXED_TEMPLATE.format(
        attacker="gemini-2.5-flash",
        evaluator="gemini-2.5-flash",
    )
    assert build_authoritativeness_warning(scan) == expected


def test_mixed_branch_mentions_mixed_evaluator() -> None:
    """The mixed copy explicitly names the partial-real / partial-stub case."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="mixed",
        scoring_valid=False,
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "Mixed-evaluator scans" in text
    assert "evaluation_mode=mixed" in text


# ---------------------------------------------------------------------------
# Engine missing / partial.
# ---------------------------------------------------------------------------


def test_engine_missing_renders_question_marks() -> None:
    """When the engine dict is empty/None, attacker + evaluator interpolate as '?'."""
    scan = _make_scan(
        mode="fast",
        evaluation_mode="stub",
        scoring_valid=False,
        engine_override={},
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "attacker=?" in text
    assert "evaluator=?" in text


def test_engine_none_renders_question_marks() -> None:
    """``scan.engine = None`` is treated as an empty dict — '?' placeholders."""
    scan = _make_scan(
        mode="fast",
        evaluation_mode="stub",
        scoring_valid=False,
    )
    # Manually replace engine with None via model_copy.
    scan = scan.model_copy(update={"engine": None})
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "attacker=?" in text
    assert "evaluator=?" in text


# ---------------------------------------------------------------------------
# Edge: unknown mode literal → safe-default to stub copy.
# ---------------------------------------------------------------------------


def test_unknown_mode_falls_back_to_stub_template() -> None:
    """A future ``Scan.mode`` literal this code does not yet understand
    triggers the safe-default stub copy rather than a coverage diagnosis it
    can't back up."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=41.0,
    )
    # Force an unknown mode by bypassing the Literal-typed constructor.
    object.__setattr__(scan, "mode", "ultra")
    text = build_authoritativeness_warning(scan)
    assert text is not None
    # Safe-default = stub-style copy.
    assert "A stub / non-LLM evaluator" in text


def test_unknown_evaluation_mode_falls_back_to_stub_template() -> None:
    """A future ``evaluation_mode`` literal this code does not yet understand
    triggers the safe-default stub copy."""
    scan = _make_scan(
        mode="full",
        evaluation_mode="real",
        scoring_valid=False,
    )
    object.__setattr__(scan, "evaluation_mode", "future_mode")
    text = build_authoritativeness_warning(scan)
    assert text is not None
    assert "A stub / non-LLM evaluator" in text


# ---------------------------------------------------------------------------
# Single-source-of-truth threshold consolidation.
# ---------------------------------------------------------------------------


def test_threshold_constants_match_swarm_finalise() -> None:
    """QA-004 §F-3 lock: ``MODE_AUTHORITATIVE_THRESHOLDS`` is the single source
    of truth used both here and by :class:`SwarmCommander` during finalise.
    A future calibration change should require updating exactly one site."""
    from agent_guardian.core.swarm import ScanMode, SwarmCommander

    swarm_table = SwarmCommander._MIN_AUTHORITATIVE_COMPLETENESS
    assert swarm_table[ScanMode.FAST] == MODE_AUTHORITATIVE_THRESHOLDS["fast"]
    assert swarm_table[ScanMode.SMART] == MODE_AUTHORITATIVE_THRESHOLDS["smart"]
    assert swarm_table[ScanMode.FULL] == MODE_AUTHORITATIVE_THRESHOLDS["full"]


# ---------------------------------------------------------------------------
# Smaller-mode parametrise — locked mapping.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected_smaller_mention", "should_offer_drop"),
    [
        ("full", "--mode smart", True),
        ("smart", "--mode fast", True),
        ("fast", None, False),
    ],
)
def test_smaller_mode_mapping_exhaustive(
    mode: str,
    expected_smaller_mention: str | None,
    should_offer_drop: bool,
) -> None:
    scan = _make_scan(
        mode=mode,
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=10.0,
        findings_count=1,
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    if should_offer_drop:
        assert expected_smaller_mention is not None
        assert expected_smaller_mention in text
        assert "smallest --mode" not in text
    else:
        assert "smallest --mode" in text
        # No "drop to --mode <smaller>" suggestion — fast is the smallest.
        assert "drop to --mode" not in text
        assert "--mode smart" not in text


# ---------------------------------------------------------------------------
# Headline acceptance pin — the cli-3a4c1d9c2840 reproduction.
# ---------------------------------------------------------------------------


def test_cli_3a4c1d9c2840_reproduction_returns_new_copy_not_stub() -> None:
    """QA-004 acceptance: re-run the scenario from QA-004 (the cli-3a4c1d9c2840
    report shape — real Gemini, low coverage, 16 findings) through
    :func:`build_authoritativeness_warning`. Must return the new low-coverage
    copy, NOT the stub-evaluator copy.
    """
    scan = _make_scan(
        mode="full",
        evaluation_mode="real",
        scoring_valid=False,
        coverage_pct=41.0,
        findings_count=16,
        attacker="gemini-3.5-flash",
        evaluator="gemini-3.5-flash",
        aivss=42,
    )
    text = build_authoritativeness_warning(scan)
    assert text is not None
    # New copy markers.
    assert "Coverage 41%" in text
    assert "95%" in text
    assert "--mode full" in text
    assert "16 findings" in text
    assert "--mode smart" in text
    # OLD (wrong) copy must NOT appear.
    assert "A stub / non-LLM evaluator" not in text
    assert "Re-run with a real --model" not in text
    # Engine echo.
    assert "attacker=gemini-3.5-flash" in text
    assert "evaluator=gemini-3.5-flash" in text
