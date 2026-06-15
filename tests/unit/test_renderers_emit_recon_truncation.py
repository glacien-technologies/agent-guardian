"""Issue #206 follow-up (rc35 deep-review M2) — recon-truncation signal
must reach every renderer alongside ``never_launched``.

Symptom we're guarding against: 31/33 fast scans in the rc35 deep-review
matrix ended with ``never_launched=[ASI02,ASI04,ASI07,ASI10]`` because
the 90s implicit recon cap timed out before fingerprinting could enumerate
the finbot testbench's declared tools. A CI consumer reading the JSON
report saw ``never_launched`` non-empty and concluded the target lacked
those agent classes — when in fact recon ran out of budget before
discovering them.

The fix: surface ``recon_truncated`` (bool) + ``recon_completion_pct``
(0-100 or None) on the JSON report and the property bag. This test
locks the wire-level contract so the field can't quietly fall off
either surface in a future refactor.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.reports.json_report import emit_json
from agent_guardian.reports.scan_props import scan_property_bag

_TS = datetime(2026, 6, 14, 12, 0, tzinfo=UTC)


def _scan(
    *,
    recon_truncated: bool = False,
    recon_completion_pct: float | None = None,
    never_launched: list[str] | None = None,
) -> Scan:
    return Scan(
        id="scan-recon-trunc",
        package_version="1.0.0rc35",
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
        mode="fast",
        engine={"commander": "real", "attacker": "real", "evaluator": "real"},
        created_at=_TS,
        never_launched=never_launched or [],
        recon_truncated=recon_truncated,
        recon_completion_pct=recon_completion_pct,
    )


# ---------------------------------------------------------------------------
# property-bag emit (powers SARIF, signed bag, dashboard SSE)
# ---------------------------------------------------------------------------


def test_property_bag_emits_recon_truncated_true_with_completion_pct() -> None:
    """The rc35 reproducer shape: recon truncated at 100% of its 90s cap
    on the finbot testbench. Both fields land on the bag.
    """
    scan = _scan(
        recon_truncated=True,
        recon_completion_pct=100.0,
        never_launched=["ASI02", "ASI04", "ASI07", "ASI10"],
    )
    bag = scan_property_bag(scan)
    assert bag.get("recon_truncated") is True, (
        "recon-truncation signal missing from property bag — SARIF / "
        "signed-bag consumers cannot tell scanner-side budget loss from "
        "genuine out-of-scope on a never_launched non-empty scan (#206 / M2)"
    )
    assert bag.get("recon_completion_pct") == 100.0


def test_property_bag_emits_recon_truncated_false_for_normal_scans() -> None:
    """Stable key, always-emit (mirrors never_launched / undertested)."""
    scan = _scan(recon_truncated=False, recon_completion_pct=60.5)
    bag = scan_property_bag(scan)
    assert bag.get("recon_truncated") is False
    assert bag.get("recon_completion_pct") == 60.5


def test_property_bag_emits_recon_completion_pct_none_when_uncapped() -> None:
    """No cap -> no percentage; downstream renderers treat None as "n/a"."""
    scan = _scan(recon_truncated=False, recon_completion_pct=None)
    bag = scan_property_bag(scan)
    assert bag.get("recon_truncated") is False
    assert bag.get("recon_completion_pct") is None


# ---------------------------------------------------------------------------
# JSON report envelope (the signed canonical artifact)
# ---------------------------------------------------------------------------


def test_json_envelope_emits_recon_truncation_signal() -> None:
    """The signed JSON report must carry the same recon-truncation pair
    so CI gates that read report.json (not the SARIF) can branch on it.
    """
    scan = _scan(
        recon_truncated=True,
        recon_completion_pct=100.0,
        never_launched=["ASI02", "ASI04", "ASI07", "ASI10"],
    )
    envelope = emit_json(scan)
    assert envelope.get("recon_truncated") is True
    assert envelope.get("recon_completion_pct") == 100.0


def test_json_envelope_clean_scan_carries_false_recon_truncated() -> None:
    """A healthy scan (recon completed in budget, never_launched empty)
    still emits the field — stable contract for downstream branchers.
    """
    scan = _scan(recon_truncated=False, recon_completion_pct=42.0)
    envelope = emit_json(scan)
    assert envelope.get("recon_truncated") is False
    assert envelope.get("recon_completion_pct") == 42.0
