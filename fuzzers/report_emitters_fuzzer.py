#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import UTC, datetime
from xml.etree import ElementTree as ET

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, band_for_score
from agent_guardian.models.tier import Tier
from agent_guardian.reports.json_report import emit_json
from agent_guardian.reports.junit import emit_junit
from agent_guardian.reports.sarif import emit_sarif


def _scan_from_text(text: str) -> Scan:
    finding = Finding(
        id="fuzz-finding",
        probe_id="FUZZ-PROBE",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success=True,
        confidence=0.5,
        summary=text or "empty",
        trigger_prompt=text[:1024] or None,
        trigger_response=text[-1024:] or None,
        created_at=datetime(2026, 6, 6, tzinfo=UTC),
    )
    return Scan(
        id="fuzz-scan",
        package_version="0.0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="fuzz",
        target_mode="prompt",
        target_ref="fuzz",
        tier=Tier.T1_CRITICAL,
        aivss=72,
        band=band_for_score(72),
        sub_scores={"fuzz": 72.0},
        findings=[finding],
        asi_scores={category: 100.0 for category in AsiCategory},
        duration_seconds=0.0,
        cost_usd=0.0,
        mode="full",
        created_at=datetime(2026, 6, 6, tzinfo=UTC),
    )


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="ignore")
    if len(text) > 4096:
        text = text[:4096]
    scan = _scan_from_text(text)
    json.dumps(emit_json(scan, redact_pii=True, sign=False))
    json.dumps(emit_sarif(scan, redact=True, validate=False))
    ET.tostring(emit_junit(scan, redact=True), encoding="utf-8")


def main() -> None:
    import sys

    import atheris

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
