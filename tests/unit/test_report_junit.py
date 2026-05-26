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


def test_emit_junit_failures_match_successful_findings() -> None:
    scan = make_scan()
    root = emit_junit(scan)
    failures = root.findall(".//testcase/failure")
    assert len(failures) == sum(1 for f in scan.findings if f.success)


def test_emit_junit_testsuites_totals_match() -> None:
    scan = make_scan()
    root = emit_junit(scan)
    assert root.get("tests") == str(len(scan.findings))
    assert root.get("failures") == str(sum(1 for f in scan.findings if f.success))


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
