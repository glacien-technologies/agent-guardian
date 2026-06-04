"""Tests for the pure CI-gate decision helper (``core.gate.evaluate_gate``)."""

from __future__ import annotations

from agent_guardian.core.gate import GateResult, evaluate_gate
from agent_guardian.models.severity import Severity
from tests.unit._report_fixtures import make_finding, make_scan


def test_all_clear_passes() -> None:
    """A clean authoritative scan with satisfied thresholds passes."""
    scan = make_scan(aivss=95, findings=[])
    result = evaluate_gate(
        scan,
        fail_under=80,
        max_critical=0,
        max_high=0,
        max_medium=0,
        max_low=0,
    )
    assert isinstance(result, GateResult)
    assert result.passed is True
    assert result.reasons == []
    assert result.counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_max_critical_exceeded_fails() -> None:
    """More critical findings than --max-critical fails the gate."""
    findings = [
        make_finding(id="c1", severity=Severity.CRITICAL),
        make_finding(id="c2", severity=Severity.CRITICAL),
    ]
    scan = make_scan(aivss=95, findings=findings)
    result = evaluate_gate(scan, max_critical=1)
    assert result.passed is False
    assert any("critical" in reason for reason in result.reasons)
    assert result.counts["critical"] == 2


def test_fail_under_floor_fails() -> None:
    """AIVSS below --fail-under fails the gate."""
    scan = make_scan(aivss=55, findings=[])
    result = evaluate_gate(scan, fail_under=80)
    assert result.passed is False
    assert any("fail-under" in reason for reason in result.reasons)


def test_non_authoritative_always_fails() -> None:
    """A non-authoritative (scoring_valid=False) scan never passes."""
    scan = make_scan(aivss=100, findings=[]).model_copy(update={"scoring_valid": False})
    # Even with no thresholds set, the gate decision must fail closed.
    result = evaluate_gate(scan)
    assert result.passed is False
    assert any("non-authoritative" in reason for reason in result.reasons)


def test_non_full_mode_fails() -> None:
    """A scan whose mode is not authoritative fails the gate."""
    scan = make_scan(aivss=100, findings=[]).model_copy(
        update={"mode": "fast", "mode_authoritative": False}
    )
    result = evaluate_gate(scan, fail_under=80)
    assert result.passed is False
    assert any("authoritative" in reason for reason in result.reasons)


def test_no_thresholds_authoritative_passes() -> None:
    """An authoritative scan with no thresholds set passes (gate is a no-op)."""
    scan = make_scan(aivss=42, findings=[])
    result = evaluate_gate(scan)
    assert result.passed is True
    assert result.reasons == []
