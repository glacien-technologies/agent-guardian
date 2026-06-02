"""Phase C.C7 — SARIF emitter surfaces Scan.calibration under runs[0].properties."""

from __future__ import annotations

from agent_guardian.models.scan import CalibrationSummary
from agent_guardian.reports.sarif import emit_sarif
from tests.unit._report_fixtures import make_scan


def test_emit_sarif_omits_calibration_when_scan_has_none() -> None:
    log = emit_sarif(make_scan())
    assert "calibration" not in log["runs"][0]["properties"]


def test_emit_sarif_surfaces_calibration_when_set() -> None:
    base = make_scan()
    calibrated = base.model_copy(
        update={
            "calibration": CalibrationSummary(
                brier_score=0.12,
                accuracy=0.85,
                n_items=10,
                judge_label="panel-of-3",
                calibration_set_version="v1",
            )
        }
    )
    log = emit_sarif(calibrated)
    props = log["runs"][0]["properties"]
    assert "calibration" in props
    assert props["calibration"]["brier_score"] == 0.12
    assert props["calibration"]["accuracy"] == 0.85
    assert props["calibration"]["n_items"] == 10
    assert props["calibration"]["judge_label"] == "panel-of-3"
    assert props["calibration"]["calibration_set_version"] == "v1"


def test_emit_sarif_with_calibration_still_validates_schema() -> None:
    # SARIF property bags are open; adding calibration must not break validation.
    base = make_scan()
    calibrated = base.model_copy(
        update={
            "calibration": CalibrationSummary(
                brier_score=0.0,
                accuracy=1.0,
                n_items=5,
                judge_label="stub",
            )
        }
    )
    # emit_sarif defaults to validate=True; an invalid payload would raise.
    log = emit_sarif(calibrated)
    assert "calibration" in log["runs"][0]["properties"]
