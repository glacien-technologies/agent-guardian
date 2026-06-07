"""JUnit XML emitter (PRD Appendix C, M13).

CI providers (Jenkins, GitLab, GitHub Actions test reporters, CircleCI) all
ingest JUnit-style XML. We map one ``<testsuites>`` to the whole scan, one
``<testsuite>`` per ASI category, and one ``<testcase>`` per finding inside
the category. **Every** :class:`Finding` in ``scan.findings`` is a reported
finding and renders with a ``<failure>`` child, so the JUnit failure count
agrees with the JSON/SARIF/Markdown finding count — a CI gate keyed on JUnit
failures cannot go green on a reported finding.

Finding text is scrubbed of PII + credential shapes via the shared
:func:`agent_guardian.core.redact.redact_finding` helper (on by default).

We use ``xml.etree.ElementTree`` and let it handle XML escaping — no
string concatenation, no XML-injection vectors via summary text.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from agent_guardian.core.redact import redact_finding
from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.reports.scan_props import finding_property_bag, scan_property_bag

__all__ = ["emit_junit", "write_junit"]

_SUITE_NAME = "agent-guardian"

# Scan-level posture/honesty signals surfaced on <testsuites> properties so a CI
# gate can fail-under on band / refuse a non-authoritative (stub/fast) run
# without parsing failure text.
_SCAN_PROPERTY_KEYS = (
    "aivss",
    "band",
    "tier",
    "mode",
    "mode_authoritative",
    "evaluation_mode",
    "scoring_valid",
    "coverage_grade",
    "cost_usd",
    "tokens_total",
    "duration_seconds",
)

# Non-sensitive per-finding evidence-chain keys surfaced as <testcase> properties
# (machine-parseable, unlike the human-readable <failure> body).
_FINDING_PROPERTY_KEYS = (
    "finding_id",
    "success",
    "verdict_v2",
    "evidence_types",
    "created_at",
)

# RoE / contract audit keys mirrored into the <testsuites> properties so the
# canonical CI artifact carries the same provenance as the signed JSON / SARIF.
_AUDIT_PROPERTY_KEYS = (
    "contract_sha256",
    "contract_version",
    "authorization_ref",
    "environment",
    "suppressed_tool_attempts",
    "egress_refused_turns",
    "started_at",
)


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
    # Machine-parseable evidence-chain fields (finding_id / verdict / success /
    # evidence_types / created_at) as a <properties> child — the <failure> body
    # below stays human-readable.
    bag = finding_property_bag(finding)
    case_props = ET.SubElement(case, "properties")
    for key in _FINDING_PROPERTY_KEYS:
        value = bag.get(key)
        if value is None:
            continue
        rendered = ",".join(str(v) for v in value) if isinstance(value, list) else str(value)
        ET.SubElement(case_props, "property", {"name": key, "value": rendered})
    # Every reported finding is a failing test (agrees with JSON/SARIF/Markdown).
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


def _append_suites_properties(suites: ET.Element, scan: Scan) -> None:
    """Mirror scan posture/honesty signals + the RoE audit envelope into a single
    <testsuites><properties> block (so a CI gate can read band / mode_authoritative
    without parsing failure text)."""
    bag = scan_property_bag(scan)
    posture = [(k, bag.get(k)) for k in _SCAN_PROPERTY_KEYS if bag.get(k) is not None]
    audit = scan.audit or {}
    audit_pairs = [
        (f"audit.{k}", audit.get(k)) for k in _AUDIT_PROPERTY_KEYS if audit.get(k) is not None
    ]
    pairs = posture + audit_pairs
    if not pairs:
        return
    props = ET.SubElement(suites, "properties")
    for name, value in pairs:
        ET.SubElement(props, "property", {"name": name, "value": str(value)})


def emit_junit(scan: Scan, *, redact: bool = True) -> ET.Element:
    """Return a JUnit ``<testsuites>`` root :class:`Element` for ``scan``."""
    findings_list = [redact_finding(f, enabled=redact) for f in scan.findings]
    grouped = _findings_by_asi(findings_list)
    total_tests = len(findings_list)
    # Every reported finding is a failing test.
    total_failures = total_tests

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
    _append_suites_properties(suites, scan)

    for category in AsiCategory:  # codeql[py/non-iterable-in-for-loop]
        findings = grouped[category]
        suite_failures = len(findings)
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


def write_junit(scan: Scan, path: Path, *, redact: bool = True) -> None:
    """Write a JUnit XML report for ``scan`` to ``path`` (UTF-8)."""
    root = emit_junit(scan, redact=redact)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(str(path), encoding="utf-8", xml_declaration=True)
