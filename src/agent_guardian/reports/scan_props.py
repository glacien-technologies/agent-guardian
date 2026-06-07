"""Shared scan/finding property bags for the non-JSON report emitters.

The canonical JSON report (:mod:`agent_guardian.reports.json_report`) is the
lossless parity bar. The SARIF / JUnit / Markdown / GitLab emitters historically
dropped most scan-level context and several non-sensitive per-finding fields, so
a consumer of those formats could not recover the posture or the evidence chain.

These two helpers return flat, JSON-safe dicts read **directly from the Scan /
Finding models** (the same source the JSON report reads), so the formats reach
parity without drifting from the JSON values. They deliberately exclude the
PII/secret-bearing ``trigger_prompt`` / ``trigger_response`` — those stay out of
CI formats (SARIF/JUnit/GitLab); the human-facing Markdown adds them separately
through the existing redaction path.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan

__all__ = ["finding_property_bag", "scan_property_bag"]


def _iso(value: datetime | Any) -> Any:
    """ISO-8601 string for a datetime (local tz when aware), else passthrough."""
    if isinstance(value, datetime):
        return value.astimezone().isoformat() if value.tzinfo else value.isoformat()
    return value


def scan_property_bag(scan: Scan) -> dict[str, Any]:
    """Flat scan-level facts shared by the SARIF/JUnit/Markdown/GitLab emitters.

    Mirrors the scan-level keys of the canonical JSON report so a consumer of any
    format can recover the posture (score + band + per-ASI), the run config
    (target / mode / engine / cost / tokens / duration), and the honesty signals
    (``evaluation_mode`` / ``scoring_valid`` / ``mode_authoritative`` /
    ``coverage_grade``) needed to tell a real assessment from a stub / partial run.
    """
    bag: dict[str, Any] = {
        "scan_id": scan.id,
        "target_ref": scan.target_ref,
        "target_mode": scan.target_mode,
        "tier": scan.tier.value,
        "mode": scan.mode,
        "aivss": scan.aivss,
        "band": scan.band.value,
        "evaluation_mode": scan.evaluation_mode,
        "scoring_valid": scan.scoring_valid,
        "mode_authoritative": scan.mode_authoritative,
        "coverage_grade": scan.coverage_grade,
        "cost_usd": scan.cost_usd,
        "tokens_total": scan.tokens_total,
        "duration_seconds": scan.duration_seconds,
        "stopped_reason": scan.stopped_reason,
        "created_at": _iso(scan.created_at),
        "asi_scores": {cat.value: score for cat, score in scan.asi_scores.items()},
        "findings_summary": scan.findings_summary(),
        "engine": dict(scan.engine) if scan.engine is not None else None,
        "undertested": list(scan.undertested),
    }
    if scan.budget is not None:
        bag["budget"] = scan.budget.model_dump(mode="json")
    if scan.completeness is not None:
        bag["completeness"] = scan.completeness.model_dump(mode="json")
    return bag


def finding_property_bag(finding: Finding) -> dict[str, Any]:
    """Flat, NON-SENSITIVE per-finding facts for the evidence chain.

    Excludes ``trigger_prompt`` / ``trigger_response`` (PII/secret-bearing). The
    CI formats use this to carry ``finding_id`` / ``verdict_v2`` / ``success`` /
    ``evidence_types`` / framework tags so a consumer can dedup, classify, and
    trace findings without the parallel JSON report.
    """
    bag: dict[str, Any] = {
        "finding_id": finding.id,
        "probe_id": finding.probe_id,
        "asi": finding.asi.value,
        "csa_category": finding.csa_category.value if finding.csa_category else None,
        "mitre_atlas": list(finding.mitre_atlas or []),
        "severity": finding.severity.value,
        "verdict_v2": finding.verdict_v2,
        "evidence_types": list(finding.evidence_types or []),
        "evidence_quote": finding.evidence_quote or "",
        "reproduced_n_of_m": finding.reproduced_n_of_m,
        "expected_safe_behavior": finding.expected_safe_behavior or "",
        "success": finding.success,
        "confidence": finding.confidence,
        "attempt_count": finding.attempt_count,
        "created_at": _iso(finding.created_at),
    }
    if finding.pov_reference:
        bag["pov_reference"] = finding.pov_reference
        bag["pov_reliability"] = finding.pov_reliability
    return bag
