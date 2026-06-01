"""Phase C.C7 — Scan.calibration field round-trip + json_report integration."""

from __future__ import annotations

from agent_guardian.models.scan import CalibrationSummary, Scan
from agent_guardian.reports.json_report import emit_json
from tests.unit._report_fixtures import make_scan


def test_scan_constructs_with_calibration_none() -> None:
    scan = make_scan()
    assert scan.calibration is None


def test_scan_constructs_with_calibration_summary() -> None:
    base = make_scan()
    summary = CalibrationSummary(
        brier_score=0.15,
        accuracy=0.80,
        n_items=10,
        judge_label="gemini:gemini-2.5-flash",
        calibration_set_version="v1",
    )
    scan = base.model_copy(update={"calibration": summary})
    assert scan.calibration is summary
    assert scan.calibration.brier_score == 0.15


def test_scan_json_round_trip_preserves_calibration() -> None:
    base = make_scan()
    summary = CalibrationSummary(
        brier_score=0.0,
        accuracy=1.0,
        n_items=10,
        judge_label="perfect",
    )
    scan = base.model_copy(update={"calibration": summary})
    payload = scan.model_dump(mode="json")
    rehydrated = Scan.model_validate(payload)
    assert rehydrated.calibration == summary


def test_calibration_summary_is_frozen() -> None:
    summary = CalibrationSummary(
        brier_score=0.0,
        accuracy=1.0,
        n_items=3,
        judge_label="x",
    )
    try:
        summary.brier_score = 0.5  # type: ignore[misc]
    except Exception:
        # WHY broad except: pydantic raises ValidationError on frozen mutation,
        # we only care the assignment is rejected.
        return
    raise AssertionError("CalibrationSummary should be frozen")


def test_emit_json_includes_calibration_when_set(tmp_path) -> None:
    base = make_scan()
    summary = CalibrationSummary(
        brier_score=0.10,
        accuracy=0.90,
        n_items=10,
        judge_label="panel-of-3",
    )
    scan = base.model_copy(update={"calibration": summary})
    payload = emit_json(scan, sign=False, memory_root=tmp_path)
    assert "calibration" in payload
    assert payload["calibration"]["brier_score"] == 0.10
    assert payload["calibration"]["accuracy"] == 0.90
    assert payload["calibration"]["judge_label"] == "panel-of-3"


def test_emit_json_omits_calibration_when_none(tmp_path) -> None:
    payload = emit_json(make_scan(), sign=False, memory_root=tmp_path)
    assert "calibration" not in payload
