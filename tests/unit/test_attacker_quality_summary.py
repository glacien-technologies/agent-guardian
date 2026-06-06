"""Issue #76 — CLI scan-end attacker-quality (rejection) summary line."""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian.cli import _attacker_quality_lines
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier


def _scan(**overrides: object) -> Scan:
    base: dict[str, object] = dict(
        id="cli-x",
        package_version="0.0.0",
        aivss_formula_version="1",
        probe_library_version="1",
        target_mode="prompt",
        target_ref="t",
        tier=Tier.T1_CRITICAL,
        aivss=100,
        band=SeverityBand.EXCELLENT,
        sub_scores={},
        findings=[],
        asi_scores={},
        duration_seconds=1.0,
        cost_usd=0.0,
        mode="full",
        created_at=datetime(2026, 6, 6, tzinfo=UTC),
    )
    base.update(overrides)
    return Scan(**base)  # type: ignore[arg-type]


def test_clean_scan_emits_no_attacker_quality_line() -> None:
    """No refusals + attacker active → silent (no noise)."""
    scan = _scan(attacker_rejection_rate=0.0, attacker_refused_turns=0, attacker_active=True)
    assert _attacker_quality_lines(scan) == []


def test_low_refusal_emits_single_line_no_marker() -> None:
    """A few refusals below the degrade threshold → one informational line."""
    scan = _scan(attacker_rejection_rate=0.10, attacker_refused_turns=1, attacker_active=True)
    lines = _attacker_quality_lines(scan)
    assert len(lines) == 1
    assert "attacker quality: 10% rejection rate" in lines[0]
    assert "1 turn(s) refused" in lines[0]
    assert not lines[0].startswith("⚠")


def test_high_refusal_non_authoritative_emits_warning_and_subline() -> None:
    """High rejection that downgraded the scan → ⚠ line + NON-AUTHORITATIVE sub-line."""
    scan = _scan(
        attacker_rejection_rate=0.45,
        attacker_refused_turns=9,
        attacker_active=True,
        mode_authoritative=False,
    )
    lines = _attacker_quality_lines(scan)
    assert len(lines) == 2
    assert lines[0].startswith("⚠ attacker quality: 45% rejection rate")
    assert "NON-AUTHORITATIVE" in lines[1]
