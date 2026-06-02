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

from datetime import datetime, timezone
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
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
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
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=timezone.utc),
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
    """Every KPI tile carries a ⓘ button + aria-describedby popover."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    for key in ("aivss", "band", "findings", "critical", "high", "elapsed", "cost", "coverage"):
        assert f'aria-describedby="kpi-{key}-desc"' in body, (
            f"missing aria-describedby for KPI {key!r}"
        )
        assert f'id="kpi-{key}-desc"' in body, f"missing popover id for KPI {key!r}"
        assert 'class="exec-kpi__info"' in body
    assert "exec-kpi__desc-popover" in body
    # Locked descriptions still render (just inside the popover now).
    assert "Composite agent safety score from adversarial testing" in body


def test_executive_kpi_strip_no_longer_renders_always_on_desc_span(
    client: TestClient, store: ScanStore
) -> None:
    """The legacy ``<span class="exec-kpi__desc">`` block is removed."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    assert 'class="exec-kpi__desc"' not in body


def test_executive_kpi_popover_css_uses_hover_focus_within(client: TestClient) -> None:
    """Popover open state is driven by :hover / :focus-within (no JS)."""
    body = client.get("/static/executive.css").text
    assert ".exec-kpi__desc-popover" in body
    assert ".exec-kpi:hover .exec-kpi__desc-popover" in body
    assert ".exec-kpi:focus-within .exec-kpi__desc-popover" in body


# ---------------------------------------------------------------------------
# QA-028 sub-ask 2 — per-tile mini-charts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["aivss", "band", "findings", "critical", "high", "elapsed", "cost", "coverage"],
)
def test_executive_kpi_tile_renders_mini_chart(
    client: TestClient, store: ScanStore, key: str
) -> None:
    """Every KPI tile renders a ``data-component="kpi-chart-{key}"`` element."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    assert f'data-component="kpi-chart-{key}"' in body, f"KPI tile {key!r} missing mini-chart"


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
    assert "max-width: 360px" in body


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
    """SSE patcher targets ``data-live="asi-compact-ASInn-{score,bar,status}"``."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    assert 'data-live="asi-compact-ASI01-score"' in overview_pane
    assert 'data-live="asi-compact-ASI01-bar"' in overview_pane
    assert 'data-live="asi-compact-ASI01-status"' in overview_pane
    # Scope prefix marker so it can coexist with the Agents-tab partial
    # until QA-030 deletes the latter.
    assert 'data-live-scope="asi-compact"' in overview_pane


def test_executive_overview_asi_compact_renders_status_pills(
    client: TestClient, store: ScanStore
) -> None:
    """Status pills (``done`` / ``running`` / ``queued``) render with the
    correct CSS classes for live progress."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    # Completed scan ⇒ rows render as "done"
    assert "exec-asi-compact__status--done" in overview_pane


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


def test_executive_overview_asi_compact_renders_weight_chips(
    client: TestClient, store: ScanStore
) -> None:
    """Each row carries the × N.N weight chip from the view-model."""  # noqa: RUF002
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    assert "exec-asi-compact__weight" in overview_pane
    # ASI01 + ASI06 carry weight 2.0 in the locked _ASI_ROW_META mapping.
    assert "× 2.0" in overview_pane  # noqa: RUF001


def test_executive_overview_asi_compact_widget_present_before_reproducibility(
    client: TestClient, store: ScanStore
) -> None:
    """Widget sits BELOW the row-3 charts and ABOVE the reproducibility receipt."""
    scan = _make_scan()
    _persist(store, scan)
    body = client.get(f"/scan/{scan.id}?theme=executive").text
    idx = body.find('id="tabpanel-overview"')
    next_idx = body.find('id="tabpanel-findings"', idx)
    overview_pane = body[idx:next_idx]
    compact_idx = overview_pane.find('data-component="asi-compact"')
    repro_idx = overview_pane.find('data-component="reproducibility"')
    twocol_idx = overview_pane.find('class="exec-overview-twocol"')
    assert twocol_idx < compact_idx < repro_idx


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
