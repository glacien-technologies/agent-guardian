"""SARIF 2.1.0 emitter (PRD Appendix C, M13).

SARIF (Static Analysis Results Interchange Format) is the lingua franca of
code-scanning tools — GitHub Advanced Security, Azure DevOps, Sonar, etc.
We emit a single ``run`` with one ``rule`` per probe ID we observed and one
``result`` per :class:`Finding`. ASI / MITRE ATLAS / CSA metadata travels
along on ``properties`` so downstream consumers don't lose it.

Finding text is scrubbed of PII + credential shapes via the shared
:func:`agent_guardian.core.redact.redact_finding` helper (on by default) so a
captured secret is never re-published to GHAS / CI / PR surfaces.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_guardian.core.redact import redact_finding
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
    props: dict[str, Any] = {
        "aivss_severity": finding.severity.value,
        "asi": finding.asi.value,
        "mitre_atlas": list(finding.mitre_atlas),
        "csa": finding.csa_category.value,
        "confidence": finding.confidence,
        "success": finding.success,
        "attempt_count": finding.attempt_count,
        "finding_id": finding.id,
    }
    # M2 Pattern 10 — surface the PoV reference + reliability when present so
    # downstream evidence-pack tooling can locate the reproducer. Omitted for
    # v1 findings that predate the PoV harness (fields are None).
    if finding.pov_reference is not None:
        props["pov_reference"] = finding.pov_reference
    if finding.pov_reliability is not None:
        props["pov_reliability"] = finding.pov_reliability
    return {
        "ruleId": finding.probe_id,
        "level": _sarif_level(finding.severity.value),
        "message": {"text": finding.summary},
        "properties": props,
    }


# Stage 1B — contract-provenance keys lifted from ``scan.audit`` onto
# ``runs[0].properties``. ``None``/absent values are omitted so the SARIF stays
# clean for partially-populated audit records.
_AUDIT_PROVENANCE_KEYS = (
    "contract_sha256",
    "contract_version",
    "authorization_ref",
    "environment",
)

# Stage 1B — budget/tool-suppression counters lifted from ``scan.audit`` into
# ``runs[0].invocations[0].properties``. ``None``/absent values are omitted.
_AUDIT_INVOCATION_KEYS = (
    "budgets_granted",
    "budgets_consumed",
    "suppressed_tool_attempts",
    "started_at",
)


def _merge_contract_provenance(properties: dict[str, Any], audit: dict[str, Any]) -> None:
    """Lift contract-provenance keys from ``audit`` onto run ``properties``.

    Mutates ``properties`` in place. Keys absent from / ``None`` in ``audit``
    are skipped so we never emit null provenance fields.
    """
    for key in _AUDIT_PROVENANCE_KEYS:
        value = audit.get(key)
        if value is not None:
            properties[key] = value


def _build_invocation(audit: dict[str, Any]) -> dict[str, Any]:
    """Build the ``runs[0].invocations[0]`` block from ``audit``.

    ``executionSuccessful`` is always ``True`` (the scan ran to completion;
    finding-level outcomes live in ``results``). Budget/suppression counters are
    nested under ``properties`` and omitted when absent / ``None``.
    """
    invocation_props: dict[str, Any] = {}
    for key in _AUDIT_INVOCATION_KEYS:
        value = audit.get(key)
        if value is not None:
            invocation_props[key] = value
    return {"executionSuccessful": True, "properties": invocation_props}


def emit_sarif(scan: Scan, *, redact: bool = True) -> dict[str, Any]:
    """Return a SARIF 2.1.0 log object describing ``scan``.

    Finding text (``summary``/``transcript_ref``/…) is scrubbed of PII +
    credential shapes when ``redact`` is true (the default — a scanner must not
    re-emit captured secrets into GHAS/CI).

    When ``scan.audit`` is present (Stage 1B), contract provenance is merged
    onto ``runs[0].properties`` and a ``runs[0].invocations`` array carrying the
    RoE budget envelope is added (SARIF 2.1.0 defines ``run.invocations`` as an
    array, not a singular ``invocation``). When ``scan.audit`` is ``None`` the
    output omits the invocations block.
    """
    findings = [redact_finding(f, enabled=redact) for f in scan.findings]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "agent-guardian",
                "version": scan.package_version,
                "informationUri": SARIF_INFO_URI,
                "semanticVersion": scan.package_version,
                "rules": _build_rules(findings),
            }
        },
        "automationDetails": {"id": scan.id},
        "results": [_build_result(f) for f in findings],
        "properties": {
            "aivss": scan.aivss,
            "band": scan.band.value,
            "tier": scan.tier.value,
            "asi_scores": {cat.value: score for cat, score in scan.asi_scores.items()},
            "aivss_formula_version": scan.aivss_formula_version,
            "probe_library_version": scan.probe_library_version,
        },
    }
    if scan.audit is not None:
        _merge_contract_provenance(run["properties"], scan.audit)
        # SARIF 2.1.0: run.invocations is an ARRAY (run.additionalProperties is
        # false, so a singular "invocation" key is rejected by strict consumers).
        run["invocations"] = [_build_invocation(scan.audit)]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif(scan: Scan, path: Path, *, redact: bool = True, indent: int = 2) -> None:
    """Write SARIF JSON to ``path`` (UTF-8, sorted keys)."""
    payload = emit_sarif(scan, redact=redact)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=indent, sort_keys=True),
        encoding="utf-8",
    )
