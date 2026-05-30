"""SARIF 2.1.0 emitter tests (M13)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_guardian.reports.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    ReportError,
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


# --- finding #2: secret redaction in SARIF result message --------------


def test_emit_sarif_redacts_secrets_in_message() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    leaky = make_finding(
        id="f_leak",
        probe_id="ASI02-TM-009",
        severity=Severity.HIGH,
        summary="leaked AKIAIOSFODNN7EXAMPLE in response",
    )
    log = emit_sarif(make_scan(findings=[leaky]))
    blob = json.dumps(log)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "[REDACTED:AWS_ACCESS_KEY]" in blob


def test_emit_sarif_redact_false_leaves_raw() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    leaky = make_finding(
        id="f_leak2",
        probe_id="ASI02-TM-010",
        severity=Severity.HIGH,
        summary="raw user@example.com",
    )
    log = emit_sarif(make_scan(findings=[leaky]), redact=False)
    assert "user@example.com" in json.dumps(log)


# --- finding #33: runtime SARIF 2.1.0 schema validation -----------------


def test_emit_sarif_validates_by_default() -> None:
    """Default emit must validate cleanly against the bundled schema.

    This is the inverse of the malformed test below — a normal scan must
    pass validation so the gate is never tripped on legitimate output.
    """
    # No exception means the validator returned no errors.
    emit_sarif(make_scan())


def test_emit_sarif_raises_report_error_on_malformed_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A payload that violates the schema must surface as ``ReportError``.

    We inject a broken payload by monkey-patching :func:`_build_invocation`
    to return a string instead of an object — SARIF 2.1.0 requires each
    invocation to be an object with ``executionSuccessful: bool``.
    """
    from agent_guardian.reports import sarif as sarif_module
    from tests.unit.reports.test_sarif_contract import _scan_with_audit

    monkeypatch.setattr(sarif_module, "_build_invocation", lambda _audit: "not an object")
    with pytest.raises(ReportError, match="SARIF schema validation failed"):
        emit_sarif(_scan_with_audit())


def test_emit_sarif_validate_false_skips_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``validate=False`` is the documented escape hatch — same malformed
    payload as above must NOT raise when validation is disabled."""
    from agent_guardian.reports import sarif as sarif_module
    from tests.unit.reports.test_sarif_contract import _scan_with_audit

    monkeypatch.setattr(sarif_module, "_build_invocation", lambda _audit: "not an object")
    # Should not raise — validation gate is off.
    log = emit_sarif(_scan_with_audit(), validate=False)
    assert log["runs"][0]["invocations"] == ["not an object"]


def test_write_sarif_raises_before_writing_on_malformed_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A schema failure must surface BEFORE any bytes hit disk —
    otherwise we'd persist a corrupt artifact in a CI bundle."""
    from agent_guardian.reports import sarif as sarif_module
    from tests.unit.reports.test_sarif_contract import _scan_with_audit

    monkeypatch.setattr(sarif_module, "_build_invocation", lambda _audit: "not an object")
    out = tmp_path / "bad.sarif"
    with pytest.raises(ReportError):
        write_sarif(_scan_with_audit(), out)
    assert not out.exists()


def test_sarif_schema_loader_is_cached() -> None:
    """The bundled schema is parsed at most once per process (lru_cache)."""
    from agent_guardian.reports.sarif import _load_sarif_schema

    a = _load_sarif_schema()
    b = _load_sarif_schema()
    assert a is b
