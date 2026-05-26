"""JUnit XML emitter (PRD Appendix C, M13).

CI providers (Jenkins, GitLab, GitHub Actions test reporters, CircleCI) all
ingest JUnit-style XML. We map one ``<testsuites>`` to the whole scan, one
``<testsuite>`` per ASI category, and one ``<testcase>`` per finding inside
the category. A failed (``success=True``) finding renders with a
``<failure>`` child; a passing one renders empty.

We use ``xml.etree.ElementTree`` and let it handle XML escaping — no
string concatenation, no XML-injection vectors via summary text.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan

__all__ = ["emit_junit", "write_junit"]

_SUITE_NAME = "agent-guardian"


def _findings_by_asi(findings: list[Finding]) -> dict[AsiCategory, list[Finding]]:
    grouped: dict[AsiCategory, list[Finding]] = {cat: [] for cat in AsiCategory}
    for finding in findings:
        grouped[finding.asi].append(finding)
    return grouped


def _testcase_for(finding: Finding) -> ET.Element:
    case = ET.Element(
        "testcase",
        {
            "name": finding.probe_id,
            "classname": f"{_SUITE_NAME}.{finding.asi.value}",
            "time": "0",
        },
    )
    if finding.success:
        failure = ET.SubElement(
            case,
            "failure",
            {
                "message": finding.summary,
                "type": finding.severity.value,
            },
        )
        # Body of <failure> carries the full detail so JUnit viewers display it.
        failure.text = (
            f"Probe: {finding.probe_id}\n"
            f"ASI: {finding.asi.value} ({asi_description(finding.asi)})\n"
            f"Severity: {finding.severity.value}\n"
            f"CSA: {finding.csa_category.value}\n"
            f"MITRE ATLAS: {', '.join(finding.mitre_atlas)}\n"
            f"Confidence: {finding.confidence:.2f}\n"
            f"Attempts: {finding.attempt_count}\n"
            f"Summary: {finding.summary}"
        )
    return case


def emit_junit(scan: Scan) -> ET.Element:
    """Return a JUnit ``<testsuites>`` root :class:`Element` for ``scan``."""
    grouped = _findings_by_asi(list(scan.findings))
    total_tests = len(scan.findings)
    total_failures = sum(1 for f in scan.findings if f.success)

    suites = ET.Element(
        "testsuites",
        {
            "name": _SUITE_NAME,
            "tests": str(total_tests),
            "failures": str(total_failures),
            "errors": "0",
            "time": f"{scan.duration_seconds:.3f}",
        },
    )

    for category in AsiCategory:
        findings = grouped[category]
        suite_failures = sum(1 for f in findings if f.success)
        suite = ET.SubElement(
            suites,
            "testsuite",
            {
                "name": category.value,
                "package": f"{_SUITE_NAME}.{category.value}",
                "tests": str(len(findings)),
                "failures": str(suite_failures),
                "errors": "0",
                "skipped": "0",
                "time": "0",
                "hostname": "agent-guardian",
            },
        )
        # ASI-level properties so consumers can surface the score in CI UIs.
        props = ET.SubElement(suite, "properties")
        ET.SubElement(
            props,
            "property",
            {
                "name": "asi_score",
                "value": str(scan.asi_scores.get(category, 100.0)),
            },
        )
        ET.SubElement(
            props,
            "property",
            {"name": "asi_description", "value": asi_description(category)},
        )
        for finding in findings:
            suite.append(_testcase_for(finding))

    return suites


def write_junit(scan: Scan, path: Path) -> None:
    """Write a JUnit XML report for ``scan`` to ``path`` (UTF-8)."""
    root = emit_junit(scan)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(str(path), encoding="utf-8", xml_declaration=True)
