"""Unit tests for the QA-028 sub-ask 2 / QA-033 view-model additions.

Pure tests against ``build_dashboard_context`` — no FastAPI / TestClient.
"""

from __future__ import annotations

from agent_guardian.server.dashboard_view import (
    build_dashboard_context,
)

# QA-065 (2026-06-04) — the standalone BAND tile and its ``_band_segment_index``
# helper were removed; the band now rides along on the AIVSS tile's sub-caption,
# so there is no longer a 5-segment band axis to index. The former
# ``test_band_segment_index_*`` cases were deleted with the helper.


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
    assert "band_index" not in data
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
