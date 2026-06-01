"""Unit tests for the QA-028 sub-ask 2 / QA-033 view-model additions.

Pure tests against ``build_dashboard_context`` — no FastAPI / TestClient.
"""

from __future__ import annotations

from agent_guardian.models.severity import SeverityBand
from agent_guardian.server.dashboard_view import (
    _band_segment_index,
    build_dashboard_context,
)


def test_band_segment_index_locked_mapping() -> None:
    """The 5 band enums map to indices 0..4 left → right."""
    assert _band_segment_index(SeverityBand.CRITICAL) == 0
    assert _band_segment_index(SeverityBand.POOR) == 1
    assert _band_segment_index(SeverityBand.WARNING) == 2
    assert _band_segment_index(SeverityBand.GOOD) == 3
    assert _band_segment_index(SeverityBand.EXCELLENT) == 4


def test_band_segment_index_unknown_and_not_evaluated_return_negative_one() -> None:
    assert _band_segment_index(None) == -1
    assert _band_segment_index(SeverityBand.NOT_EVALUATED) == -1


def test_kpi_chart_data_present_with_no_scan() -> None:
    ctx = build_dashboard_context(
        scan_id="cli-x",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8080",
        version_label="test",
    )
    data = ctx.payload["kpi_chart_data"]
    assert data["aivss_pct"] == 0.0
    assert data["band_index"] == -1
    assert data["severity_mix"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    assert data["coverage_total"] == 10
    assert data["coverage_covered"] == 0


def test_kpi_chart_data_aivss_pct_clamped_to_zero_hundred() -> None:
    """AIVSS pct is clamped to [0, 100] via _fmt_pct."""
    ctx = build_dashboard_context(
        scan_id="cli-x",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8080",
        version_label="test",
    )
    data = ctx.payload["kpi_chart_data"]
    assert 0.0 <= data["aivss_pct"] <= 100.0
