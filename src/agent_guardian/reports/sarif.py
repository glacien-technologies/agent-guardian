"""SARIF 2.1.0 emitter (PRD Appendix C, M13).

SARIF (Static Analysis Results Interchange Format) is the lingua franca of
code-scanning tools — GitHub Advanced Security, Azure DevOps, Sonar, etc.
We emit a single ``run`` with one ``rule`` per probe ID we observed and one
``result`` per :class:`Finding`. ASI / MITRE ATLAS / CSA metadata travels
along on ``properties`` so downstream consumers don't lose it.

We deliberately do *not* depend on ``jsonschema`` — instead, tests assert
structural invariants (``$schema``, ``version``, ``runs[0]`` shape).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_guardian.models.asi import asi_description
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan

__all__ = [
    "SARIF_INFO_URI",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "emit_sarif",
    "write_sarif",
]

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_INFO_URI = "https://agentguardian.ai"


_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _sarif_level(severity: str) -> str:
    """Map AgentGuardian severity to SARIF level (``error|warning|note``)."""
    return _SEVERITY_TO_LEVEL.get(severity, "warning")


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.probe_id in rules:
            continue
        rules[finding.probe_id] = {
            "id": finding.probe_id,
            "name": finding.probe_id,
            "shortDescription": {"text": f"AgentGuardian probe {finding.probe_id}"},
            "fullDescription": {
                "text": (
                    f"AgentGuardian probe {finding.probe_id} — "
                    f"{asi_description(finding.asi)} "
                    f"(CSA: {finding.csa_category.value})."
                )
            },
            "defaultConfiguration": {"level": _sarif_level(finding.severity.value)},
            "properties": {
                "asi": finding.asi.value,
                "csa": finding.csa_category.value,
                "mitre_atlas": list(finding.mitre_atlas),
            },
        }
    # Sort rule IDs so output is deterministic.
    return [rules[rule_id] for rule_id in sorted(rules)]


def _build_result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.probe_id,
        "level": _sarif_level(finding.severity.value),
        "message": {"text": finding.summary},
        "properties": {
            "aivss_severity": finding.severity.value,
            "asi": finding.asi.value,
            "mitre_atlas": list(finding.mitre_atlas),
            "csa": finding.csa_category.value,
            "confidence": finding.confidence,
            "success": finding.success,
            "attempt_count": finding.attempt_count,
            "finding_id": finding.id,
        },
    }


def emit_sarif(scan: Scan) -> dict[str, Any]:
    """Return a SARIF 2.1.0 log object describing ``scan``."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-guardian",
                        "version": scan.package_version,
                        "informationUri": SARIF_INFO_URI,
                        "semanticVersion": scan.package_version,
                        "rules": _build_rules(list(scan.findings)),
                    }
                },
                "automationDetails": {"id": scan.id},
                "results": [_build_result(f) for f in scan.findings],
                "properties": {
                    "aivss": scan.aivss,
                    "band": scan.band.value,
                    "tier": scan.tier.value,
                    "asi_scores": {cat.value: score for cat, score in scan.asi_scores.items()},
                    "aivss_formula_version": scan.aivss_formula_version,
                    "probe_library_version": scan.probe_library_version,
                },
            }
        ],
    }


def write_sarif(scan: Scan, path: Path, *, indent: int = 2) -> None:
    """Write SARIF JSON to ``path`` (UTF-8, sorted keys)."""
    payload = emit_sarif(scan)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=indent, sort_keys=True),
        encoding="utf-8",
    )
