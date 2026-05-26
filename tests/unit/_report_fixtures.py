"""Shared helpers for M13 report-emitter tests."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, band_for_score
from agent_guardian.models.tier import Tier

UTC = timezone.utc


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "id": "f_001",
        "probe_id": "ASI01-GH-007",
        "asi": AsiCategory.ASI01,
        "mitre_atlas": ["AML.T0054"],
        "csa_category": CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        "severity": Severity.HIGH,
        "attempt_count": 3,
        "success": True,
        "confidence": 0.9,
        "summary": "Agent leaked secret to external tool.",
        "created_at": datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def make_scan(
    *,
    aivss: int = 72,
    findings: list[Finding] | None = None,
    asi_scores: dict[AsiCategory, float] | None = None,
) -> Scan:
    if findings is None:
        findings = [
            make_finding(id="f_001", severity=Severity.CRITICAL, probe_id="ASI01-GH-001"),
            make_finding(
                id="f_002",
                severity=Severity.HIGH,
                probe_id="ASI02-TM-005",
                asi=AsiCategory.ASI02,
                csa_category=CsaCategory.AUTHORIZATION_CONTROL_HIJACKING,
                summary="Tool misuse: dropped admin privs.",
            ),
            make_finding(
                id="f_003",
                severity=Severity.MEDIUM,
                probe_id="ASI05-CE-002",
                asi=AsiCategory.ASI05,
                csa_category=CsaCategory.AGENT_CRITICAL_SYSTEM_INTERACTION,
                summary="Code-exec attempt was sandboxed but reachable.",
                success=False,
            ),
            make_finding(
                id="f_004",
                severity=Severity.LOW,
                probe_id="ASI10-DR-001",
                asi=AsiCategory.ASI10,
                csa_category=CsaCategory.HALLUCINATION_EXPLOITATION,
                summary="Mild drift detected.",
                confidence=0.4,
            ),
        ]
    if asi_scores is None:
        asi_scores = {cat: 90.0 for cat in AsiCategory}
        asi_scores[AsiCategory.ASI01] = 40.0
        asi_scores[AsiCategory.ASI02] = 60.0

    return Scan(
        id="sc_01ABCDEF01ABCDEF01ABCDEF",
        package_version="0.0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="0.0.0",
        target_mode="prompt",
        target_ref="prompt.txt",
        tier=Tier.T1_CRITICAL,
        aivss=aivss,
        band=band_for_score(aivss),
        sub_scores={
            "prompt_injection_resistance": 80.0,
            "tool_safety": 70.0,
            "memory_integrity": 90.0,
        },
        findings=findings,
        asi_scores=asi_scores,
        duration_seconds=12.5,
        cost_usd=0.04,
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
