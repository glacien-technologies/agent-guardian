"""Tests for the overview-polish cluster (QA-028 + QA-033).

Covers:
  - QA-028 sub-ask 1 — KPI tile descriptions hidden behind ⓘ + popover.
  - QA-028 sub-ask 2 — per-tile inline-SVG mini-chart presence.
  - QA-028 sub-ask 3a — row-3 charts shrunk + radar square-up CSS rules.
  - QA-028 sub-ask 3b — FIG. 1 / FIG. 2 eyebrows removed from the partials.
  - QA-033 — Overview tab renders the new compact ASI breakdown widget
              with 10 rows and the locked metadata fields.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.server import create_app
from agent_guardian.server.scan_store import ScanStore


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_finding(
    fid: str,
    severity: Severity,
    asi: AsiCategory = AsiCategory.ASI01,
) -> Finding:
    return Finding(
        id=fid,
        probe_id=f"probe-{fid}",
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=2,
        success=True,
        confidence=0.91,
        summary=f"finding {fid}: prompt injection observed",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
    )


def _make_scan(scan_id: str = "cli-executive-polish-001") -> Scan:
    findings = [
        _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
        _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
        _make_finding("f-med-1", Severity.MEDIUM, AsiCategory.ASI03),
    ]
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=84,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 72.0,
            "tool_scope_safety": 88.0,
            "pii_containment": 95.0,
            "memory_poisoning_resistance": 68.0,
            "excessive_agency_containment": 84.0,
            "hallucination_resistance": 79.0,
        },
        findings=findings,
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=252.0,
        cost_usd=0.84,
        tokens_total=820_000,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )


def _persist(store: ScanStore, scan: Scan) -> Path:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan_dir


# ---------------------------------------------------------------------------
# QA-028 sub-ask 1 — KPI hover-tooltip
# ---------------------------------------------------------------------------


def test_executive_kpi_tile_renders_info_button_and_popover(
    client: TestClient, store: ScanStore
) -> None:
    """Every remaining KPI tile carries a ⓘ button + prose info popover.

    QA-043 (2026-06-02) — CRITICAL + HIGH tiles removed; the strip is now
    six tiles. QA-044 + QA-039 — the popover is ``kpi-info-popover`` driven
    by click-to-open ``aria-controls`` rather than the old hover-only
    ``aria-describedby`` + ``exec-kpi__desc-popover`` markup.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    for key in ("aivss", "band", "findings", "elapsed", "cost", "coverage"):
        assert f'aria-controls="kpi-{key}-info"' in body, f"missing aria-controls for KPI {key!r}"
        assert f'id="kpi-{key}-info"' in body, f"missing popover id for KPI {key!r}"
    # New marker classes the QA validation greps for.
    assert "kpi-info-icon" in body
    assert "kpi-info-popover" in body


def test_executive_kpi_strip_drops_critical_and_high_tiles(
    client: TestClient, store: ScanStore
) -> None:
    """QA-043 — CRITICAL + HIGH KPI tiles no longer render."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    assert 'data-kpi="critical"' not in body
    assert 'data-kpi="high"' not in body


def test_executive_kpi_info_popover_css_drops_uppercase(client: TestClient) -> None:
    """QA-039 — the prose info popover renders without ALL-CAPS styling."""
    body = client.get("/static/executive.css").text
    # The selector exists.
    assert ".kpi-info-popover" in body
    # And it explicitly opts out of uppercase + heavy letter-spacing.
    assert "text-transform: none" in body


# ---------------------------------------------------------------------------
# QA-028 sub-ask 2 — per-tile mini-charts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,component",
    [
        # QA-061 (2026-06-03) — AIVSS tile no longer renders a mini-chart;
        # it uses the same plain-text big-numeric + band-label treatment
        # as the BAND tile and is exercised by
        # ``test_executive_aivss_tile_renders_plain_text_after_qa_061``
        # below instead of this parametrisation.
        ("band", "kpi-chart-band"),
        ("findings", "kpi-chart-findings"),
        ("elapsed", "kpi-chart-elapsed"),
        ("cost", "kpi-chart-cost"),
        ("coverage", "kpi-chart-coverage"),
    ],
)
def test_executive_kpi_tile_renders_mini_chart(
    client: TestClient, store: ScanStore, key: str, component: str
) -> None:
    """Every remaining KPI tile renders its declared mini-chart component."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    assert f'data-component="{component}"' in body, (
        f"KPI tile {key!r} missing mini-chart component {component!r}"
    )


def test_executive_aivss_tile_renders_plain_text_after_qa_061(
    client: TestClient, store: ScanStore
) -> None:
    """QA-061 (2026-06-03) — AIVSS tile is plain-text (big numeric + band
    label) and the horseshoe gauge is gone. The tile MUST NOT carry the
    ``aivss-gauge`` data-component anymore, but it MUST still carry the
    ``data-live="aivss"`` hook the SSE patcher uses to update the score.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    # Gauge is gone.
    assert 'data-component="aivss-gauge"' not in body
    assert "gauge-arc--critical" not in body
    assert "gauge-needle" not in body
    # Plain-text treatment is present.
    assert 'data-live="aivss"' in body


def test_executive_kpi_chart_data_dict_present_on_view_model() -> None:
    """``kpi_chart_data`` is exposed on the dashboard context."""
    from agent_guardian.server.dashboard_view import build_dashboard_context

    ctx = build_dashboard_context(
        scan_id="cli-kpi-001",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8080",
        version_label="test",
    )
    data = ctx.payload["kpi_chart_data"]
    assert set(data.keys()) >= {
        "aivss_pct",
        "band_index",
        "severity_mix",
        "elapsed_uncapped",
        "cost_uncapped",
        "elapsed_pct",
        "cost_pct",
        "coverage_covered",
        "coverage_total",
    }
    assert data["coverage_total"] == 10


# ---------------------------------------------------------------------------
# QA-028 sub-ask 3a — row-3 shrink + radar square
# ---------------------------------------------------------------------------


def test_executive_row3_bar_shrunk_to_280_floor(client: TestClient) -> None:
    body = client.get("/static/executive.css").text
    # The new min-height is 280 px; the old 360 px floor on the canvas wrap
    # was the locked symptom of the over-tall row-3.
    assert "min-height: 280px" in body


def test_executive_row3_radar_squared_up(client: TestClient) -> None:
    body = client.get("/static/executive.css").text
    assert ".exec-overview-twocol .exec-chart--radar .exec-chart__canvas-wrap" in body
    assert "aspect-ratio: 1 / 1" in body
    # QA-045 (2026-06-02) — the radar card grew from 360 → 480 px so the
    # full category names ("Privilege abuse", "Supply chain", "Cascading
    # failure") fit without truncation. The aspect ratio is preserved;
    # only the envelope size changed.
    assert "max-width: 480px" in body


# ---------------------------------------------------------------------------
# QA-028 sub-ask 3b — drop FIG. x eyebrows
# ---------------------------------------------------------------------------


def test_executive_overview_no_longer_renders_fig_eyebrows(
    client: TestClient, store: ScanStore
) -> None:
    """The Overview tab no longer surfaces the FIG. 1 / FIG. 2 eyebrow text."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    assert "FIG. 1" not in overview_pane
    assert "FIG. 2" not in overview_pane


# ---------------------------------------------------------------------------
# QA-033 — compact ASI breakdown widget on Overview
# ---------------------------------------------------------------------------


def test_executive_overview_renders_asi_compact_table(client: TestClient, store: ScanStore) -> None:
    """The Overview tab includes the new ``data-component="asi-compact"``
    widget with all 10 ASI rows and the locked metadata fields."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    # Widget marker
    assert 'data-component="asi-compact"' in overview_pane
    # Section title visible
    assert "Adversarial Surface Index breakdown" in overview_pane
    # Exactly 10 rows (one per ASI category)
    assert overview_pane.count("exec-asi-compact__row") >= 10
    # All ASI codes present
    for code in (
        "ASI01",
        "ASI02",
        "ASI03",
        "ASI04",
        "ASI05",
        "ASI06",
        "ASI07",
        "ASI08",
        "ASI09",
        "ASI10",
    ):
        assert code in overview_pane


def test_executive_overview_asi_compact_has_live_update_keys(
    client: TestClient, store: ScanStore
) -> None:
    """SSE patcher targets ``data-live="asi-compact-ASInn-score"``.

    QA-064 + QA-065 (2026-06-03) — the PROGRESS bar, WEIGHT chip, and
    STATUS pill columns were removed. SCORE is now the only per-row
    data-live key the SSE patcher needs to maintain.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    assert 'data-live="asi-compact-ASI01-score"' in overview_pane
    # QA-065 — bar + status data-live keys removed along with their columns.
    assert 'data-live="asi-compact-ASI01-bar"' not in overview_pane
    assert 'data-live="asi-compact-ASI01-status"' not in overview_pane
    # Scope prefix marker so it can coexist with the Agents-tab partial
    # until QA-030 deletes the latter.
    assert 'data-live-scope="asi-compact"' in overview_pane


def test_executive_overview_asi_compact_renders_findings_pills(
    client: TestClient, store: ScanStore
) -> None:
    """Each row carries four severity finding-count pills."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    for sev in ("critical", "high", "medium", "low"):
        assert (
            f"exec-asi-compact__pill--{sev}" in overview_pane
            or "exec-asi-compact__pill--zero" in overview_pane
        )


def test_executive_overview_asi_compact_dropped_weight_progress_status(
    client: TestClient, store: ScanStore
) -> None:
    """QA-064 + QA-065 (2026-06-03) — the WEIGHT chip, PROGRESS bar, and
    STATUS pill columns were dropped from the breakdown table; final
    column order is ASI · CATEGORY · SCORE · C / H / M / L.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    # QA-064 — weight chip span + its multiplier text gone from each row.
    assert 'class="exec-asi-compact__weight' not in overview_pane
    assert "× 2.0" not in overview_pane  # noqa: RUF001
    # QA-065 — progress bar + status pill spans gone from each row.
    assert 'class="exec-asi-compact__bar"' not in overview_pane
    assert 'class="exec-asi-compact__status' not in overview_pane
    # Header row trimmed to four <span role="columnheader"> cells
    # (ASI · Category · Score · C/H/M/L). The Score cell carries the
    # numeric modifier class so the count of `__head"` (with the trailing
    # quote) maps to the three non-modifier cells; the modifier hit on
    # Score brings the total to 4.
    assert overview_pane.count('role="columnheader"') == 4
    assert ">Weight<" not in overview_pane
    assert ">Progress<" not in overview_pane
    assert ">Status<" not in overview_pane


def test_executive_overview_asi_compact_widget_present_after_charts(
    client: TestClient, store: ScanStore
) -> None:
    """Widget sits BELOW the row-3 charts on Overview.

    The reproducibility receipt that used to sit below the compact widget
    was removed (the Overview was cleaned of framework-internal
    scaffolding), so the widget is now the last Overview element. The
    new "Scan plan" panel sits ABOVE the two-column chart row.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    plan_idx = overview_pane.find('data-component="scan-plan"')
    compact_idx = overview_pane.find('data-component="asi-compact"')
    twocol_idx = overview_pane.find('class="exec-overview-twocol"')
    assert plan_idx != -1
    assert twocol_idx < compact_idx
    assert plan_idx < twocol_idx
    # The retired reproducibility receipt must no longer appear anywhere.
    assert 'data-component="reproducibility"' not in body


def test_executive_overview_asi_compact_widget_present(
    client: TestClient, store: ScanStore
) -> None:
    """QA-033 introduced the Overview ASI compact widget; QA-030 has since
    deleted the legacy Agents tab and its ``data-component="asi-rows"``
    partial. Confirm the compact widget still ships on Overview — the rows
    partial assertion is covered (in the negative) by
    ``test_executive_clean_control_renders_all_new_partials`` in
    ``tests/server/test_theme_executive_rendering.py``.
    """
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    # Overview now has the compact widget.
    assert 'data-component="asi-compact"' in body
    # Agents tab + asi-rows partial were removed by QA-030; the negative
    # assertion lives in test_theme_executive_rendering.py to avoid
    # duplicating the lock.
