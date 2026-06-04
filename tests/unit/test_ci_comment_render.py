"""Tests for the shared CI comment renderer (``ci.comment.render_comment``)."""

from __future__ import annotations

from agent_guardian.ci.comment import MARKER, render_comment
from agent_guardian.core.gate import evaluate_gate
from agent_guardian.models.severity import humanise_band
from tests.unit._report_fixtures import make_scan


def test_marker_is_first_non_blank_line() -> None:
    scan = make_scan()
    gate = evaluate_gate(scan, fail_under=80)
    body = render_comment(scan, gate)
    first_non_blank = next(line for line in body.splitlines() if line.strip())
    assert first_non_blank == MARKER


def test_aivss_band_and_findings_rendered() -> None:
    scan = make_scan(aivss=72)
    gate = evaluate_gate(scan)
    body = render_comment(scan, gate)
    assert "72/100" in body
    assert humanise_band(scan.band) in body
    # Default fixture has four findings.
    assert f"{len(scan.findings)} finding" in body
    # Top findings table shows probe ids.
    assert "ASI01-GH-001" in body


def test_gate_verdict_shown_passed() -> None:
    scan = make_scan(aivss=95, findings=[])
    gate = evaluate_gate(scan, fail_under=80, max_critical=0)
    body = render_comment(scan, gate)
    assert gate.passed is True
    assert "Gate: PASSED" in body


def test_gate_verdict_shown_failed_with_reasons() -> None:
    scan = make_scan(aivss=55)
    gate = evaluate_gate(scan, fail_under=80)
    body = render_comment(scan, gate)
    assert gate.passed is False
    assert "Gate: FAILED" in body
    # Each failing reason is rendered.
    for reason in gate.reasons:
        assert reason in body


def test_clean_scan_renders_no_findings_note() -> None:
    scan = make_scan(aivss=98, findings=[])
    gate = evaluate_gate(scan)
    body = render_comment(scan, gate)
    assert "came back clean" in body
