"""Issue #207 follow-up — every renderer must emit the never_launched field.

PR #208 added ``Scan.never_launched`` as a first-class persisted field
parallel to ``undertested``. This follow-up wires the field through the
report surfaces so the persistence work is operator-visible:

* ``reports/json_report.py`` — flat ``never_launched`` array
* ``reports/scan_props.py`` — property bag (used by SARIF + signature
  payloads)
* ``reports/markdown.py`` — "Categories not applicable to this target"
  notice block

Renderers that surface a colored per-ASI score (dashboard, PDF) need a
display-layer N/A branch — that change is more invasive and lands in
the same PR but is exercised by integration tests rather than these
flat-emission unit tests.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.reports.markdown import emit_markdown
from agent_guardian.reports.scan_props import scan_property_bag
from agent_guardian.server.dashboard_view import _asi_rows

_TS = datetime(2026, 6, 14, 12, 0, tzinfo=UTC)


def _scan(*, never_launched: list[str] | None = None) -> Scan:
    return Scan(
        id="scan-na-render",
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
    )


# ---------------------------------------------------------------------------
# scan_property_bag — the shared property-bag emitter.
# ---------------------------------------------------------------------------


def test_scan_property_bag_emits_never_launched_when_present() -> None:
    scan = _scan(never_launched=["ASI04", "ASI07"])
    bag = scan_property_bag(scan)
    assert "never_launched" in bag, (
        "scan_property_bag must surface never_launched alongside "
        "undertested so SARIF / signed-bag / json_report consumers can "
        "render N/A. Without it the field round-trips through the model "
        "but never reaches the wire."
    )
    assert bag["never_launched"] == ["ASI04", "ASI07"]


def test_scan_property_bag_emits_never_launched_as_empty_list_when_unset() -> None:
    """Always-emit (even when empty) so downstream consumers can branch
    on a stable key instead of `None`-vs-missing ambiguity. Mirrors the
    pattern undertested already follows.
    """
    scan = _scan(never_launched=[])
    bag = scan_property_bag(scan)
    assert bag.get("never_launched") == []


# ---------------------------------------------------------------------------
# Markdown report — visible-to-operator notice line.
# ---------------------------------------------------------------------------


def test_markdown_emits_never_launched_notice() -> None:
    """When ``never_launched`` is non-empty, the markdown report renders a
    "Categories not applicable" notice so a reader doesn't read the per-
    ASI heatmap's 0 next to that category as a finding.
    """
    scan = _scan(never_launched=["ASI07"])
    md = emit_markdown(scan)
    # Some recognisable phrasing of the not-applicable signal — we don't
    # pin the exact prose so the writer can iterate, but the category
    # name + an N/A-shaped marker must appear.
    assert "ASI07" in md
    lower = md.lower()
    assert any(needle in lower for needle in ("not applicable", "n/a", "skipped"))


def test_markdown_omits_never_launched_notice_when_empty() -> None:
    """No noise on the happy path: an empty never_launched produces no
    "not applicable" block in the rendered report.
    """
    scan = _scan(never_launched=[])
    md = emit_markdown(scan)
    lower = md.lower()
    assert "not applicable for this target" not in lower


# ---------------------------------------------------------------------------
# Dashboard _asi_rows — the per-ASI heatmap that motivated the entire fix.
# ---------------------------------------------------------------------------


def test_dashboard_asi_rows_label_never_launched_as_na() -> None:
    """When a category is in ``Scan.never_launched`` the dashboard's
    per-ASI row must render its ``score_label`` as ``"N/A"`` (not the
    misleading ``"0"`` that previously appeared) and must NOT mark it
    as ``is_attention`` (no red styling on a row that's correctly
    skipped).
    """
    scan = _scan(never_launched=["ASI07"])
    # Mimic the asi_scores shape compute_aivss writes: 0.0 in the data
    # layer for the untested-is-not-clean floor.
    scan = scan.model_copy(update={"asi_scores": {**scan.asi_scores, AsiCategory.ASI07: 0.0}})
    findings_by_asi: dict[str, dict[str, int]] = {}
    rows = _asi_rows(scan, findings_by_asi)
    row_asi07 = next(r for r in rows if r["code"] == "ASI07")
    assert row_asi07["score_label"] == "N/A", (
        "Dashboard heatmap must render N/A for never-launched ASI rows. "
        "Pre-fix the deep-red '0' next to (e.g.) 'Agent Discovery / A2A' "
        "on a target without multi-agent surface read as a finding."
    )
    assert row_asi07["is_not_applicable"] is True
    assert row_asi07["is_attention"] is False, (
        "Never-launched rows must not paint as 'attention' — they're "
        "skipped by design, not problematic."
    )


def test_dashboard_asi_rows_unchanged_for_launched_categories() -> None:
    """Regression guard: never_launched=[] must produce identical row
    shape to the pre-#207 behaviour for categories that were actually
    launched.
    """
    scan = _scan(never_launched=[])
    findings_by_asi: dict[str, dict[str, int]] = {}
    rows = _asi_rows(scan, findings_by_asi)
    row_asi01 = next(r for r in rows if r["code"] == "ASI01")
    assert row_asi01["score_label"] == "100"
    assert row_asi01["is_not_applicable"] is False
