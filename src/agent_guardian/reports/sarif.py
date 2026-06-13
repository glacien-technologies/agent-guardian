"""SARIF 2.1.0 emitter (PRD Appendix C, M13).

SARIF (Static Analysis Results Interchange Format) is the lingua franca of
code-scanning tools — GitHub Advanced Security, Azure DevOps, Sonar, etc.
We emit a single ``run`` with one ``rule`` per probe ID we observed and one
``result`` per :class:`Finding`. ASI / MITRE ATLAS / CSA metadata travels
along on ``properties`` so downstream consumers don't lose it.

Finding text is scrubbed of PII + credential shapes via the shared
:func:`agent_guardian.core.redact.redact_finding` helper (on by default) so a
captured secret is never re-published to GHAS / CI / PR surfaces.

The emitter validates its output against the bundled SARIF 2.1.0 JSON Schema
before returning (``validate=True`` by default). A malformed payload raises
:class:`ReportError` — downstream consumers (GHAS, Sonar, …) reject invalid
SARIF silently, so catching shape regressions at the source matters more than
saving a millisecond. The escape hatch ``validate=False`` is reserved for
benchmarks and internal callers that have already validated upstream.
"""

from __future__ import annotations

import functools
import json
import logging
import re
from pathlib import Path
from typing import Any

import jsonschema

from agent_guardian.core.redact import redact_finding
from agent_guardian.models.asi import asi_description
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.reports.scan_props import scan_property_bag

__all__ = [
    "SARIF_INFO_URI",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "ReportError",
    "emit_sarif",
    "write_sarif",
]

_LOG = logging.getLogger(__name__)

# Bundled SARIF 2.1.0 schema (mirrored from OASIS sarif-spec). Lives next to
# this module so it ships in the wheel; the lru_cache below means we parse it
# at most once per process.
_SARIF_SCHEMA_PATH = Path(__file__).with_name("sarif-2.1.0.schema.json")


class ReportError(Exception):
    """Raised when a report payload fails its schema-validation contract.

    Used by :func:`emit_sarif` / :func:`write_sarif` when the emitted SARIF
    log does not validate against the bundled SARIF 2.1.0 schema. The error
    message carries a compact summary of the first violation so a human
    operator (or CI failure log) sees exactly what is wrong.
    """


@functools.lru_cache(maxsize=1)
def _load_sarif_schema() -> dict[str, Any]:
    """Return the bundled SARIF 2.1.0 schema, parsed once per process."""
    try:
        text = _SARIF_SCHEMA_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        _LOG.error("SARIF schema not found at %s: %s", _SARIF_SCHEMA_PATH, exc)
        raise ReportError(f"bundled SARIF schema missing: {_SARIF_SCHEMA_PATH}") from exc
    schema: dict[str, Any] = json.loads(text)
    return schema


def _validate_sarif(payload: dict[str, Any]) -> None:
    """Validate ``payload`` against the bundled SARIF 2.1.0 schema.

    Raises :class:`ReportError` (chained from :class:`jsonschema.ValidationError`)
    on the first violation; logs the violation at ERROR before raising so
    operators can diagnose without inspecting the exception chain.
    """
    schema = _load_sarif_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(payload))
    if not errors:
        return
    first = errors[0]
    path = "/".join(str(p) for p in first.absolute_path) or "<root>"
    summary = f"SARIF schema validation failed at {path}: {first.message}"
    _LOG.error("%s (total violations: %d)", summary, len(errors))
    raise ReportError(summary) from first


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_INFO_URI = "https://agentguardian.io"


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


# GitHub Code Scanning rejects any SARIF result without at least one location
# ("locationFromSarifResult: expected at least one location"). AgentGuardian
# findings are behavioural — a runtime attack on a live agent, not a static
# defect tied to a file:line — so there is no natural source location. We
# synthesise a single stable, non-empty, repo-relative-looking URI from the
# scan target so every result carries a valid ``physicalLocation`` and GHAS
# accepts the upload. This sentinel is the last-resort value when the target
# ref is empty, so the SARIF never violates the GHAS contract.
_FALLBACK_TARGET_URI = "agentguardian/scan-target"

# Matches a leading URI scheme (``https://`` …) so HTTP endpoint targets become
# clean relative-looking paths (GHAS treats a scheme-qualified absolute URI as
# non-source and would not surface it inline).
_URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _artifact_uri(target_mode: str, target_ref: str) -> str:
    """Best-effort repo-relative URI describing the scanned target.

    Always returns a non-empty string (falling back to
    :data:`_FALLBACK_TARGET_URI`) so every SARIF result can carry a location:

    - ``http``      → endpoint with its scheme + surrounding slashes stripped
      (``https://a.example.com/chat`` → ``a.example.com/chat``).
    - ``framework`` / ``code`` → the part before any ``:attr`` selector; a
      dotted module is turned into a path (``app.agent:graph`` → ``app/agent.py``)
      so it usually maps onto the real source file, while an existing path
      (contains ``/`` or ends ``.py``) is kept as-is.
    - ``prompt``    → the prompt file path as-is.
    """
    ref = (target_ref or "").strip()
    if not ref:
        return _FALLBACK_TARGET_URI
    if target_mode == "http":
        stripped = _URI_SCHEME_RE.sub("", ref).strip("/")
        return stripped or _FALLBACK_TARGET_URI
    # Drop a trailing ``:attr`` / ``:obj`` selector shared by code + framework
    # refs (e.g. ``module:graph``); the scan target is the module/file itself.
    head = ref.split(":", 1)[0].strip() or ref
    if target_mode == "prompt":
        return head
    # framework / code (and any future mode): keep real paths, otherwise map a
    # dotted module onto a file path.
    if "/" in head or head.endswith(".py"):
        return head
    return head.replace(".", "/") + ".py"


def _build_locations(uri: str) -> list[dict[str, Any]]:
    """One file-level physical location pointing at the scan target.

    GHAS requires ``physicalLocation.artifactLocation.uri``; the ``region`` pins
    a deterministic ``startLine`` so the codeql-action's fingerprinting is
    stable across re-runs.
    """
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 1},
            }
        }
    ]


def _build_result(finding: Finding, target_uri: str) -> dict[str, Any]:
    # #134 — an informational finding (success=False: unconfirmed
    # ``vulnerable`` / capability-exposure note) must not annotate CI at its
    # severity face value; it is emitted at SARIF level ``note`` so a build
    # gate keyed on error/warning only trips on confirmed compromises. The
    # original severity stays in ``properties.aivss_severity``.
    level = _sarif_level(finding.severity.value) if finding.success else "note"
    props: dict[str, Any] = {
        "aivss_severity": finding.severity.value,
        "asi": finding.asi.value,
        "mitre_atlas": list(finding.mitre_atlas),
        "csa": finding.csa_category.value,
        "confidence": finding.confidence,
        "success": finding.success,
        "attempt_count": finding.attempt_count,
        "finding_id": finding.id,
        # Evidence-chain fields (non-sensitive — no trigger text): the judge
        # verdict + corroboration signals + timestamp for post-hoc analysis.
        "evidence_types": list(finding.evidence_types or []),
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }
    if finding.verdict_v2 is not None:
        props["verdict_v2"] = finding.verdict_v2
    # M2 Pattern 10 — surface the PoV reference + reliability when present so
    # downstream evidence-pack tooling can locate the reproducer. Omitted for
    # v1 findings that predate the PoV harness (fields are None).
    if finding.pov_reference is not None:
        props["pov_reference"] = finding.pov_reference
    if finding.pov_reliability is not None:
        props["pov_reliability"] = finding.pov_reliability
    result: dict[str, Any] = {
        "ruleId": finding.probe_id,
        "level": level,
        "message": {"text": finding.summary},
        # GHAS requires >=1 location per result; all findings share the single
        # target location (the scanned agent), distinguished by fingerprint.
        "locations": _build_locations(target_uri),
        "properties": props,
    }
    # A stable per-finding fingerprint stops GHAS from collapsing distinct
    # findings that share a probe (ruleId) and the single target location into
    # one alert. ``finding.id`` is unique per finding within a scan.
    if finding.id:
        result["partialFingerprints"] = {"agentGuardianFindingId/v1": str(finding.id)}
    return result


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


def emit_sarif(scan: Scan, *, redact: bool = True, validate: bool = True) -> dict[str, Any]:
    """Return a SARIF 2.1.0 log object describing ``scan``.

    Finding text (``summary``/``transcript_ref``/…) is scrubbed of PII +
    credential shapes when ``redact`` is true (the default — a scanner must not
    re-emit captured secrets into GHAS/CI).

    When ``scan.audit`` is present (Stage 1B), contract provenance is merged
    onto ``runs[0].properties`` and a ``runs[0].invocations`` array carrying the
    RoE budget envelope is added (SARIF 2.1.0 defines ``run.invocations`` as an
    array, not a singular ``invocation``). When ``scan.audit`` is ``None`` the
    output omits the invocations block.

    When ``validate`` is true (the default), the payload is checked against the
    bundled SARIF 2.1.0 schema before being returned; a malformed payload
    raises :class:`ReportError`. Pass ``validate=False`` only when the caller
    has already validated upstream (benchmarks, internal pipeline glue).
    """
    findings = [redact_finding(f, enabled=redact) for f in scan.findings]
    # One synthetic location for the whole run — the scanned agent target.
    target_uri = _artifact_uri(scan.target_mode, scan.target_ref)
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
        "results": [_build_result(f, target_uri) for f in findings],
        "properties": {
            # Full scan-level context (target / mode / engine / cost / tokens /
            # duration / honesty signals + posture) so a SARIF consumer can
            # recover the run without the parallel JSON report.
            **scan_property_bag(scan),
            "aivss_formula_version": scan.aivss_formula_version,
            "probe_library_version": scan.probe_library_version,
        },
    }
    if scan.audit is not None:
        _merge_contract_provenance(run["properties"], scan.audit)
        # SARIF 2.1.0: run.invocations is an ARRAY (run.additionalProperties is
        # false, so a singular "invocation" key is rejected by strict consumers).
        run["invocations"] = [_build_invocation(scan.audit)]
    # C7 — calibration travels under runs[0].properties (propertyBag is open).
    if scan.calibration is not None:
        run["properties"]["calibration"] = scan.calibration.model_dump(mode="json")
    payload: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    if validate:
        _validate_sarif(payload)
    return payload


def write_sarif(
    scan: Scan,
    path: Path,
    *,
    redact: bool = True,
    indent: int = 2,
    validate: bool = True,
) -> None:
    """Write SARIF JSON to ``path`` (UTF-8, sorted keys).

    ``validate`` is forwarded to :func:`emit_sarif`; the default behaviour is
    to validate before writing so we never persist a malformed report.
    """
    payload = emit_sarif(scan, redact=redact, validate=validate)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=indent, sort_keys=True),
        encoding="utf-8",
    )
