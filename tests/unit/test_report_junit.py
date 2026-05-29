"""JUnit XML emitter tests (M13)."""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from agent_guardian.models.asi import AsiCategory
from agent_guardian.reports.junit import emit_junit, write_junit
from tests.unit._report_fixtures import make_scan


def test_emit_junit_returns_testsuites_root() -> None:
    root = emit_junit(make_scan())
    assert root.tag == "testsuites"
    assert root.get("name") == "agent-guardian"


def test_emit_junit_has_one_suite_per_asi() -> None:
    root = emit_junit(make_scan())
    suites = root.findall("testsuite")
    assert len(suites) == len(list(AsiCategory))
    names = {s.get("name") for s in suites}
    assert names == {cat.value for cat in AsiCategory}


def test_emit_junit_failure_for_every_finding() -> None:
    # Report-integrity invariant: every Finding in scan.findings is a reported
    # finding and renders a <failure>, regardless of the (latent) success flag,
    # so the JUnit failure count agrees with JSON/SARIF/Markdown.
    scan = make_scan()
    root = emit_junit(scan)
    failures = root.findall(".//testcase/failure")
    assert len(failures) == len(scan.findings)


def test_emit_junit_does_not_hide_success_false_findings() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    hidden = make_finding(
        id="f_hidden",
        probe_id="ASI03-PA-009",
        severity=Severity.HIGH,
        summary="Suppressed-but-reported finding.",
        success=False,
    )
    scan = make_scan(findings=[hidden])
    root = emit_junit(scan)
    assert root.get("tests") == "1"
    assert root.get("failures") == "1"
    assert len(root.findall(".//testcase/failure")) == 1


def test_emit_junit_testsuites_totals_match() -> None:
    scan = make_scan()
    root = emit_junit(scan)
    assert root.get("tests") == str(len(scan.findings))
    assert root.get("failures") == str(len(scan.findings))


def test_emit_junit_testcase_names_are_probe_ids() -> None:
    scan = make_scan()
    root = emit_junit(scan)
    case_names = {tc.get("name") for tc in root.findall(".//testcase")}
    assert case_names == {f.probe_id for f in scan.findings}


def test_write_junit_produces_parseable_xml(tmp_path: Path) -> None:
    path = tmp_path / "junit.xml"
    write_junit(make_scan(), path)
    tree = ET.parse(str(path))
    assert tree.getroot().tag == "testsuites"


def test_write_junit_escapes_summary_safely(tmp_path: Path) -> None:
    """Special characters in summaries must not break the XML."""
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    nasty = make_finding(
        id="f_xss",
        probe_id="ASI01-GH-XSS",
        severity=Severity.CRITICAL,
        summary='<script>alert("x")</script> & friends',
    )
    scan = make_scan(findings=[nasty])
    path = tmp_path / "junit.xml"
    write_junit(scan, path)
    tree = ET.parse(str(path))
    fail = tree.find(".//testcase/failure")
    assert fail is not None
    # ElementTree should have escaped the angle brackets, the text reads back literally.
    assert fail.get("message") is not None
    assert "<script>" in (fail.get("message") or "")


def test_emit_junit_includes_asi_property_per_suite() -> None:
    root = emit_junit(make_scan())
    asi_props = root.findall(".//testsuite/properties/property[@name='asi_score']")
    assert len(asi_props) == len(list(AsiCategory))


def test_emit_junit_mirrors_audit_provenance() -> None:
    scan = make_scan().model_copy(
        update={
            "audit": {
                "contract_sha256": "c" * 64,
                "authorization_ref": "JIRA-9",
                "suppressed_tool_attempts": 47,
                "egress_refused_turns": 6,
            }
        }
    )
    root = emit_junit(scan)
    props = {p.get("name"): p.get("value") for p in root.findall("./properties/property")}
    assert props["audit.contract_sha256"] == "c" * 64
    assert props["audit.authorization_ref"] == "JIRA-9"
    assert props["audit.suppressed_tool_attempts"] == "47"
    assert props["audit.egress_refused_turns"] == "6"


def test_emit_junit_redacts_secrets_in_summary() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    leaky = make_finding(
        id="f_leak",
        probe_id="ASI02-TM-009",
        severity=Severity.HIGH,
        summary="leaked sk-proj-ABCDEFGHIJKLMNOPQRSTUV and AKIAIOSFODNN7EXAMPLE",
    )
    scan = make_scan(findings=[leaky])
    root = emit_junit(scan)
    xml = ET.tostring(root, encoding="unicode")
    assert "sk-proj-ABCDEFGHIJKLMNOPQRSTUV" not in xml
    assert "AKIAIOSFODNN7EXAMPLE" not in xml
    assert "[REDACTED:OPENAI_API_KEY]" in xml
    assert "[REDACTED:AWS_ACCESS_KEY]" in xml


def test_emit_junit_redact_false_leaves_text_raw() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    leaky = make_finding(
        id="f_leak2",
        probe_id="ASI02-TM-010",
        severity=Severity.HIGH,
        summary="raw user@example.com",
    )
    scan = make_scan(findings=[leaky])
    root = emit_junit(scan, redact=False)
    xml = ET.tostring(root, encoding="unicode")
    assert "user@example.com" in xml
