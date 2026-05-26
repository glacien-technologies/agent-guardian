"""SARIF 2.1.0 emitter tests (M13)."""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.reports.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    emit_sarif,
    write_sarif,
)
from tests.unit._report_fixtures import make_scan


def test_emit_sarif_has_schema_and_version() -> None:
    log = emit_sarif(make_scan())
    assert log["$schema"] == SARIF_SCHEMA
    assert log["version"] == SARIF_VERSION


def test_emit_sarif_has_one_run() -> None:
    log = emit_sarif(make_scan())
    assert isinstance(log["runs"], list)
    assert len(log["runs"]) == 1


def test_emit_sarif_tool_driver_metadata() -> None:
    log = emit_sarif(make_scan())
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agent-guardian"
    assert driver["informationUri"].startswith("https://")
    assert "version" in driver
    assert isinstance(driver["rules"], list)


def test_emit_sarif_results_match_findings() -> None:
    scan = make_scan()
    log = emit_sarif(scan)
    results = log["runs"][0]["results"]
    assert len(results) == len(scan.findings)
    ids = {r["ruleId"] for r in results}
    assert ids == {f.probe_id for f in scan.findings}


def test_emit_sarif_levels_for_each_severity() -> None:
    log = emit_sarif(make_scan())
    levels = {r["level"] for r in log["runs"][0]["results"]}
    # Our fixture has critical/high/medium/low → error, error, warning, note.
    assert "error" in levels
    assert "warning" in levels
    assert "note" in levels


def test_emit_sarif_rules_are_unique_and_sorted() -> None:
    log = emit_sarif(make_scan())
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids == sorted(rule_ids)
    assert len(rule_ids) == len(set(rule_ids))


def test_emit_sarif_run_properties_carry_aivss() -> None:
    scan = make_scan()
    log = emit_sarif(scan)
    props = log["runs"][0]["properties"]
    assert props["aivss"] == scan.aivss
    assert props["band"] == scan.band.value
    assert props["tier"] == scan.tier.value


def test_write_sarif_emits_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "report.sarif"
    write_sarif(make_scan(), path)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["$schema"] == SARIF_SCHEMA
    assert parsed["version"] == SARIF_VERSION
    assert "runs" in parsed


def test_emit_sarif_each_result_has_properties() -> None:
    log = emit_sarif(make_scan())
    for result in log["runs"][0]["results"]:
        props = result["properties"]
        for key in ("aivss_severity", "asi", "mitre_atlas", "csa"):
            assert key in props
