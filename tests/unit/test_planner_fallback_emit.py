"""Issue #215 — planner_fallback never reaches the on-disk report.

The SwarmCommander tracks ``self._planner_fallback`` ("adaptive" /
"uniform" / None) to record whether the commander produced an adaptive
per-agent plan or whether the swarm fell back to the uniform brief
(commander LLM refused, parsed-bad, etc). Pre-fix the field was tracked
in memory but never persisted on the Scan model, so operators auditing
a non-authoritative scan could not tell adaptive vs uniform without
grep-ing run.log line-by-line. Per the rc35 deep-review M1: zero
matches across 30 report.json + 35 run.log files.

The fix persists ``planner_fallback`` on the Scan model and emits it
through json_report + scan_props (the SARIF / signed bag feed). Default
``None`` means the commander didn't run (recon-only scan / commander
skipped by the "no operator or inferred goal" gate -- issue #220 / L5).
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.reports.json_report import emit_json
from agent_guardian.reports.scan_props import scan_property_bag


def _scan(*, planner_fallback: str | None) -> Scan:
    return Scan(
        id="scan-planner",
        package_version="1.0.0rc36",
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="http",
        target_ref="https://example.test/chat",
        tier=Tier.T2_HIGH,
        aivss=43,
        band=SeverityBand.POOR,
        sub_scores={
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 70.0,
            "pii_containment": 70.0,
            "memory_poisoning_resistance": 70.0,
            "excessive_agency_containment": 70.0,
            "hallucination_resistance": 70.0,
        },
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=250.0,
        cost_usd=0.05,
        tokens_total=50_000,
        mode="full",
        engine={"commander": "real", "attacker": "real", "evaluator": "real"},
        created_at=datetime(2026, 6, 15, tzinfo=UTC),
        planner_fallback=planner_fallback,
    )


def test_scan_planner_fallback_defaults_to_none() -> None:
    """Back-compat: older Scan JSON on disk that predates the field still
    deserialises with None (no migration needed)."""
    scan = _scan(planner_fallback=None)
    assert scan.planner_fallback is None


def test_scan_planner_fallback_accepts_adaptive() -> None:
    scan = _scan(planner_fallback="adaptive")
    assert scan.planner_fallback == "adaptive"


def test_scan_planner_fallback_accepts_uniform() -> None:
    scan = _scan(planner_fallback="uniform")
    assert scan.planner_fallback == "uniform"


def test_json_envelope_emits_planner_fallback() -> None:
    """The signed JSON report must carry planner_fallback so CI gates +
    dashboards can branch on it."""
    envelope = emit_json(_scan(planner_fallback="adaptive"))
    assert envelope.get("planner_fallback") == "adaptive"


def test_json_envelope_emits_planner_fallback_none_when_skipped() -> None:
    """``None`` survives the round-trip — operators reading the report
    can distinguish 'commander skipped' from 'planner_fallback missing
    field' (a pre-fix Scan)."""
    envelope = emit_json(_scan(planner_fallback=None))
    assert "planner_fallback" in envelope
    assert envelope["planner_fallback"] is None


def test_property_bag_emits_planner_fallback() -> None:
    """The property bag (SARIF + signed bag + dashboard SSE) carries the
    same field as the JSON envelope -- mirrors the never_launched /
    recon_truncated emit pattern."""
    bag = scan_property_bag(_scan(planner_fallback="uniform"))
    assert bag.get("planner_fallback") == "uniform"
