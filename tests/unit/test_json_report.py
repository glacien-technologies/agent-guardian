"""Regression tests for coverage_grade + undertested wiring through the JSON report.

The bug they pin: ``coverage_grade`` and ``undertested`` were computed
inside ``compute_aivss`` but never persisted on the Scan or emitted into
the signed JSON / Markdown reports, so an operator could not gate on them.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian._version import __version__ as _v
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.reports.json_report import emit_json
from agent_guardian.reports.markdown import emit_markdown


def _make_scan(
    *,
    aivss: int = 72,
    band: SeverityBand = SeverityBand.WARNING,
    undertested: list[str] | None = None,
    coverage_grade: str = "A",
) -> Scan:
    return Scan(
        id="sc_coverage_grade_test_01ABCDEF",
        package_version=_v,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="prompt.txt",
        tier=Tier.T2_HIGH,
        aivss=aivss,
        band=band,
        sub_scores={},
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=1.0,
        cost_usd=0.0,
        mode="full",
        undertested=undertested or [],
        coverage_grade=coverage_grade,  # type: ignore[arg-type]
        created_at=datetime(2026, 5, 28, tzinfo=UTC),
    )


def test_scan_model_accepts_coverage_grade() -> None:
    scan = _make_scan(coverage_grade="F")
    assert scan.coverage_grade == "F"


def test_scan_model_defaults_coverage_grade_to_a_for_backcompat() -> None:
    scan = Scan(
        id="sc_default_test_01ABCDEF",
        package_version=_v,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="prompt.txt",
        tier=Tier.T2_HIGH,
        aivss=100,
        band=SeverityBand.EXCELLENT,
        sub_scores={},
        findings=[],
        asi_scores={},
        duration_seconds=1.0,
        cost_usd=0.0,
        mode="full",
        created_at=datetime(2026, 5, 28, tzinfo=UTC),
    )
    # Older Scan JSON on disk that lacked the field must still deserialise.
    assert scan.coverage_grade == "A"


def test_emit_json_includes_coverage_grade_and_undertested() -> None:
    scan = _make_scan(
        coverage_grade="C",
        undertested=["ASI05", "ASI08"],
    )
    payload = emit_json(scan, sign=False, redact_pii=False)
    assert payload["coverage_grade"] == "C"
    assert payload["undertested"] == ["ASI05", "ASI08"]


def test_emit_json_undertested_defaults_to_empty_list() -> None:
    scan = _make_scan()
    payload = emit_json(scan, sign=False, redact_pii=False)
    assert payload["undertested"] == []
    assert payload["coverage_grade"] == "A"


def test_emit_json_coverage_grade_is_inside_the_signature() -> None:
    """coverage_grade must be folded in BEFORE signing so it cannot be tampered with."""
    scan = _make_scan(coverage_grade="F")
    payload = emit_json(scan, sign=True)
    assert payload["coverage_grade"] == "F"
    assert "signatures" in payload  # signing happened over the coverage_grade.


def test_emit_markdown_includes_coverage_grade_in_badge_line() -> None:
    scan = _make_scan(coverage_grade="F")
    md = emit_markdown(scan)
    assert "**Coverage** `F`" in md


def test_emit_markdown_includes_thinly_tested_notice_when_undertested_nonempty() -> None:
    scan = _make_scan(
        coverage_grade="C",
        undertested=["ASI05", "ASI08"],
    )
    md = emit_markdown(scan)
    assert "Thinly tested" in md
    assert "ASI05" in md
    assert "ASI08" in md


def test_emit_markdown_omits_thinly_tested_notice_when_undertested_empty() -> None:
    scan = _make_scan()
    md = emit_markdown(scan)
    assert "Thinly tested" not in md
