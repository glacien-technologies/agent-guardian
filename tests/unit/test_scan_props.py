"""Shared property-bag helpers used by the SARIF/JUnit/Markdown/GitLab emitters."""

from __future__ import annotations

import json

from agent_guardian.reports.scan_props import finding_property_bag, scan_property_bag
from tests.unit._report_fixtures import make_finding, make_scan


def test_scan_property_bag_carries_posture_config_and_honesty_signals() -> None:
    scan = make_scan(aivss=43)
    bag = scan_property_bag(scan)
    # Posture
    assert bag["aivss"] == 43
    assert bag["band"] == scan.band.value
    assert bag["tier"] == scan.tier.value
    assert bag["asi_scores"]  # per-ASI sub-scores present
    assert "findings_summary" in bag
    # Run config
    for k in ("target_ref", "target_mode", "mode", "cost_usd", "tokens_total", "duration_seconds"):
        assert k in bag, f"missing config key {k}"
    # Honesty signals — the whole point: a stub/fast run must be distinguishable.
    for k in ("evaluation_mode", "scoring_valid", "mode_authoritative", "coverage_grade"):
        assert k in bag, f"missing honesty signal {k}"
    # JSON-safe
    json.dumps(bag)


def test_finding_property_bag_carries_evidence_chain_but_no_trigger_text() -> None:
    finding = make_finding()
    bag = finding_property_bag(finding)
    for k in (
        "finding_id",
        "probe_id",
        "asi",
        "severity",
        "verdict_v2",
        "evidence_types",
        "success",
    ):
        assert k in bag, f"missing evidence-chain key {k}"
    assert bag["finding_id"] == finding.id
    # PII/secret-bearing trigger text must NOT be in the CI property bag.
    assert "trigger_prompt" not in bag
    assert "trigger_response" not in bag
    json.dumps(bag)
