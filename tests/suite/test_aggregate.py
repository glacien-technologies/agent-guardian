"""Suite aggregation — cross-scan summary rows + trust flags + folder listing."""

from __future__ import annotations

from agent_guardian.suite.aggregate import (
    format_summary_lines,
    report_authority,
    summary_row,
)


def _report(**over: object) -> dict:
    base = {
        "scan_id": "cli-abc123",
        "aivss": 41,
        "band": "POOR",
        "tier": "T2",
        "findings": [{}] * 62,
        "findings_summary": {"critical": 1, "high": 3, "medium": 8, "low": 50},
        "coverage": {"attacker_refusal_rate": 0.02},
        "evaluation_mode": "real",
        "scoring_valid": True,
        "mode_authoritative": True,
        "coverage_grade": "A",
        "undertested": [],
    }
    base.update(over)
    return base


def test_clean_real_scan_is_authoritative() -> None:
    ok, reasons = report_authority(_report())
    assert ok is True
    assert reasons == []


def test_stub_mode_is_not_authoritative() -> None:
    ok, reasons = report_authority(_report(evaluation_mode="stub"))
    assert ok is False
    assert any("evaluation_mode" in r for r in reasons)


def test_invalid_scoring_not_authoritative() -> None:
    ok, _reasons = report_authority(_report(scoring_valid=False))
    assert ok is False


def test_high_refusal_not_authoritative() -> None:
    ok, reasons = report_authority(_report(coverage={"attacker_refusal_rate": 0.5}))
    assert ok is False
    assert any("refusal" in r for r in reasons)


def test_low_coverage_grade_not_authoritative() -> None:
    ok, reasons = report_authority(_report(coverage_grade="F"))
    assert ok is False
    assert any("coverage" in r for r in reasons)


def test_undertested_flags_non_authoritative() -> None:
    ok, _reasons = report_authority(_report(undertested=["ASI06"]))
    assert ok is False


def test_summary_row_surfaces_core_fields() -> None:
    row = summary_row(
        name="finbot",
        scan_id="cli-abc123",
        scan_dir="/home/u/.agentguardian/scans/cli-abc123",
        report=_report(),
        status="ok",
        exit_code=0,
        reports={"json": "/out/reports/finbot.json"},
        console_log="/out/finbot.console.log",
    )
    assert row["name"] == "finbot"
    assert row["scan_id"] == "cli-abc123"
    assert row["aivss"] == 41
    assert row["band"] == "POOR"
    assert row["tier"] == "T2"
    assert row["findings_total"] == 62
    assert row["findings_by_severity"]["high"] == 3
    assert row["refusal_rate"] == 0.02
    assert row["authoritative"] is True
    assert row["status"] == "ok"
    assert row["log_folder"].endswith("cli-abc123")


def test_error_row_has_no_report() -> None:
    row = summary_row(
        name="broken",
        scan_id=None,
        scan_dir=None,
        report=None,
        status="error",
        exit_code=3,
        reports={},
        console_log="/out/broken.console.log",
    )
    assert row["status"] == "error"
    assert row["aivss"] is None
    assert row["authoritative"] is False


def test_format_lists_every_scan_log_folder() -> None:
    rows = [
        summary_row(
            name="a",
            scan_id="cli-1",
            scan_dir="/s/cli-1",
            report=_report(scan_id="cli-1"),
            status="ok",
            exit_code=0,
            reports={},
            console_log="/o/a.log",
        ),
        summary_row(
            name="b",
            scan_id="cli-2",
            scan_dir="/s/cli-2",
            report=_report(scan_id="cli-2"),
            status="ok",
            exit_code=0,
            reports={},
            console_log="/o/b.log",
        ),
    ]
    text = "\n".join(format_summary_lines(rows))
    assert "Scan log folders:" in text
    assert "/s/cli-1" in text
    assert "/s/cli-2" in text
