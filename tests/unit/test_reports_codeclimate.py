"""GitLab Code Quality (CodeClimate) emitter tests (CI/CD feature)."""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.models.severity import Severity
from agent_guardian.reports.codeclimate import emit_codeclimate, write_codeclimate
from tests.unit._report_fixtures import make_finding, make_scan


def test_one_finding_yields_one_valid_entry() -> None:
    scan = make_scan(findings=[make_finding()])
    entries = emit_codeclimate(scan)
    assert len(entries) == 1
    entry = entries[0]
    # GitLab Code Quality requires these keys (GitLab ignores the extra open
    # ``properties`` bag we add for the evidence chain + scan posture).
    assert {"description", "check_name", "fingerprint", "severity", "location"} <= set(entry)
    assert "properties" in entry
    assert entry["properties"]["finding_id"]  # evidence chain present
    assert entry["description"] == "Agent leaked secret to external tool."
    assert entry["check_name"] == "ASI01-GH-007"
    assert entry["severity"] in {"info", "minor", "major", "critical", "blocker"}
    assert entry["location"]["path"] == "agentguardian/ASI01.md"
    assert entry["location"]["lines"]["begin"] == 1


def test_severity_mapping() -> None:
    # HIGH -> major; MEDIUM -> minor; LOW -> info.
    assert (
        emit_codeclimate(make_scan(findings=[make_finding(severity=Severity.HIGH)]))[0]["severity"]
        == "major"
    )
    assert (
        emit_codeclimate(make_scan(findings=[make_finding(severity=Severity.MEDIUM)]))[0][
            "severity"
        ]
        == "minor"
    )
    assert (
        emit_codeclimate(make_scan(findings=[make_finding(severity=Severity.LOW)]))[0]["severity"]
        == "info"
    )
    # CRITICAL + success -> blocker; CRITICAL + not-success -> critical.
    assert (
        emit_codeclimate(
            make_scan(findings=[make_finding(severity=Severity.CRITICAL, success=True)])
        )[0]["severity"]
        == "blocker"
    )
    assert (
        emit_codeclimate(
            make_scan(findings=[make_finding(severity=Severity.CRITICAL, success=False)])
        )[0]["severity"]
        == "critical"
    )


def test_fingerprint_is_stable_and_run_independent() -> None:
    # Same probe_id/ASI/severity -> identical fingerprint, even when run-specific
    # fields (id, confidence, attempt_count) differ.
    base = make_scan(findings=[make_finding(id="f_001", confidence=0.9, attempt_count=3)])
    other = make_scan(findings=[make_finding(id="f_999", confidence=0.1, attempt_count=11)])
    fp_a = emit_codeclimate(base)[0]["fingerprint"]
    fp_b = emit_codeclimate(other)[0]["fingerprint"]
    assert fp_a == fp_b
    # sha256 hex digest shape.
    assert len(fp_a) == 64
    assert all(c in "0123456789abcdef" for c in fp_a)
    # A different probe changes the fingerprint.
    changed = make_scan(findings=[make_finding(probe_id="ASI02-TM-001")])
    assert emit_codeclimate(changed)[0]["fingerprint"] != fp_a


def test_write_codeclimate_roundtrips(tmp_path: Path) -> None:
    scan = make_scan(findings=[make_finding()])
    out = tmp_path / "nested" / "gl-code-quality-report.json"
    write_codeclimate(scan, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded == emit_codeclimate(scan)
