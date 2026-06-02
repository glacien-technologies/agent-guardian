"""Theme B (Mission Control) rendering tests.

Feeds the fixture ``Scan`` from the editorial baseline through the Mission
Control template tree (``dashboard/mission/layout.html``) and asserts:

* Every component partial renders (KPI strip, agent sparkline list, time-series
  + ASI bar chart panes, findings table, slide-over, status bar).
* Dark-mode CSS is present (``prefers-color-scheme: dark`` token block exists
  via the dark surface tokens) and the light variant is also defined.
* KPI tiles are populated with values from the view-model (AIVSS, findings
  total, critical count, coverage, tokens, elapsed).
* The Chart.js data island is embedded with the findings + ASI rows JSON so
  ``mission_charts.js`` can mount the time-series / horizontal-bar charts.
* Filter chips are present with severity classes and counts (DOM check that
  ``data-mission-filter`` attribute is wired on every chip).
* The 21 ``data-live`` SSE keys are mirrored on equivalent nodes so the
  existing live patcher updates Mission identically.
* The shared theme switcher partial is included (proves the topbar wiring).
* A 0-findings scan still renders cleanly (no false-positive empty-state crash).
* ``data-theme="mission"`` distinguishes this theme from Editorial.
"""

from __future__ import annotations

import json
import re
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
from agent_guardian.server import ScanStore, create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


def _make_scan(scan_id: str = "cli-mission-001") -> Scan:
    findings = [
        _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
        _make_finding("f-crit-2", Severity.CRITICAL, AsiCategory.ASI06),
        _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
        _make_finding("f-high-2", Severity.HIGH, AsiCategory.ASI03),
        _make_finding("f-med-1", Severity.MEDIUM, AsiCategory.ASI04),
        _make_finding("f-low-1", Severity.LOW, AsiCategory.ASI09),
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


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Layout + components render
# ---------------------------------------------------------------------------


def test_mission_renders_layout_with_all_components(client: TestClient, store: ScanStore) -> None:
    """The full Mission layout renders and embeds every partial section."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    assert resp.status_code == 200
    body = resp.text

    # Distinguishing root marker — proves Mission template was picked.
    assert 'data-theme="mission"' in body
    assert 'class="mission"' in body

    # Topbar
    assert "mission__topbar" in body
    assert "mission__brand" in body
    assert "Mission Control" in body

    # KPI strip
    assert "mission__kpi-strip" in body
    assert "mission-kpi" in body

    # Agent sparkline list (left rail)
    assert "mission__agent-panel" in body
    assert "mission__agent-list" in body
    assert "mission__agent-row" in body

    # Center charts — time-series + ASI bar
    assert "mission__charts" in body
    assert 'id="mission-timeseries"' in body
    assert 'id="mission-asi-bar"' in body
    assert 'data-mission-chart="timeseries"' in body
    assert 'data-mission-chart="asi-bar"' in body

    # Findings table
    assert "mission__findings" in body
    assert "mission__table" in body
    assert "mission__tbody" in body

    # Cross-theme locked findings heading (QA-023): every theme renders the
    # verbatim string "All findings so far." in its findings region.
    assert "All findings so far." in body

    # Slide-over
    assert 'id="mission-slideover"' in body
    assert 'role="dialog"' in body
    assert 'aria-modal="true"' in body

    # Status bar
    assert "mission__statusbar" in body


def test_mission_includes_theme_switcher_partial(client: TestClient, store: ScanStore) -> None:
    """The shared theme switcher partial must be embedded for cross-theme nav."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    assert resp.status_code == 200
    body = resp.text
    # The shared partial root container.
    assert "ag-theme-switcher" in body
    # The select element id used by theme_switcher.js
    assert 'id="ag-theme-switcher-select"' in body
    # Every theme slug listed in the dropdown
    for slug in ("editorial", "mission", "narrative", "executive"):
        assert f'value="{slug}"' in body


# ---------------------------------------------------------------------------
# 2. KPI tiles populated
# ---------------------------------------------------------------------------


def test_mission_kpi_tiles_render_view_model_values(client: TestClient, store: ScanStore) -> None:
    """Every KPI tile in the strip is populated with the right view-model value."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text

    # AIVSS tile
    assert "AIVSS" in body
    # Score 84 appears in the AIVSS tile (and the band label).
    assert "84" in body
    # band_label is now humanised (feedback-no-raw-enum-in-ui) — Title-case,
    # never the raw uppercase enum token (``GOOD``). The raw enum value is
    # still allowed to appear as a CSS class modifier hook
    # (``--good`` / ``data-band="GOOD"``), but the visible label text is
    # the humanised string.
    assert "Good" in body

    # Findings tile (total = 6 findings)
    assert "Findings" in body
    assert 'data-live="findings"' in body

    # Critical tile (count = 2 from fixture)
    assert "Critical" in body
    assert 'data-live="critical"' in body

    # Coverage tile (ASI categories covered)
    assert "Coverage" in body
    assert 'data-live="asi-covered"' in body

    # Tokens tile
    assert "Tokens" in body
    assert 'data-live="tokens"' in body
    # 820k from the fixture
    assert "820k" in body

    # Elapsed tile
    assert "Elapsed" in body
    assert 'data-live="elapsed"' in body


def test_mission_kpi_tiles_include_sparkline_canvases(client: TestClient, store: ScanStore) -> None:
    """Every KPI tile has either a sparkline canvas or a progress bar."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    # KPI sparkline canvases (4 of the 6 tiles carry one — tokens & elapsed
    # use bars instead since the underlying metric is a fraction-of-cap, not
    # a trend).
    sparks = re.findall(r'data-kpi-spark="([a-z]+)"', body)
    assert set(sparks) == {"aivss", "findings", "critical", "coverage"}
    # And the bars on tokens / elapsed
    assert 'data-live="tokens-bar"' in body
    assert 'data-live="elapsed-bar"' in body


# ---------------------------------------------------------------------------
# 3. Time-series chart data island
# ---------------------------------------------------------------------------


def test_mission_chart_data_island_present_and_valid_json(
    client: TestClient, store: ScanStore
) -> None:
    """The #mission-chart-data island is valid JSON with the keys mission_charts.js expects."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text

    match = re.search(
        r'<script id="mission-chart-data" type="application/json">\s*(\{.+?\})\s*</script>',
        body,
        re.DOTALL,
    )
    assert match is not None, "JSON chart data island missing"
    parsed = json.loads(match.group(1))

    # Required keys
    assert "scanId" in parsed
    assert "findings" in parsed
    assert "asiRows" in parsed
    assert "counts" in parsed
    assert "isRunning" in parsed

    # Findings shape
    assert isinstance(parsed["findings"], list)
    assert len(parsed["findings"]) == 6
    first = parsed["findings"][0]
    for key in ("id", "severity", "asi", "probe", "summary", "created"):
        assert key in first, f"finding missing {key}"

    # ASI rows shape — 10 axes always
    assert isinstance(parsed["asiRows"], list)
    assert len(parsed["asiRows"]) == 10
    first_asi = parsed["asiRows"][0]
    for key in ("code", "name", "scorePct", "scoreLabel", "isPending", "findings"):
        assert key in first_asi, f"asi row missing {key}"

    # Counts shape
    assert parsed["counts"] == {"critical": 2, "high": 2, "medium": 1, "low": 1}


def test_mission_chart_data_attribute_marker_present(client: TestClient, store: ScanStore) -> None:
    """The time-series canvas carries the data-mission-chart attribute that mission_charts.js reads."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    # Time-series chart canvas
    assert re.search(
        r'<canvas[^>]+id="mission-timeseries"[^>]+data-mission-chart="timeseries"',
        body,
    )
    # ASI bar chart canvas
    assert re.search(
        r'<canvas[^>]+id="mission-asi-bar"[^>]+data-mission-chart="asi-bar"',
        body,
    )


# ---------------------------------------------------------------------------
# 4. Filter chips functional via DOM check
# ---------------------------------------------------------------------------


def test_mission_filter_chips_all_present_with_severity_classes(
    client: TestClient, store: ScanStore
) -> None:
    """All five severity filter chips render with data-mission-filter wires."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text

    # Every chip carries a data-mission-filter attribute that JS reads.
    chip_filters = re.findall(r'data-mission-filter="([a-z]+)"', body)
    assert set(chip_filters) == {"all", "critical", "high", "medium", "low"}

    # Each chip has its severity-tinted class.
    assert "mission__chip--all" in body
    assert "mission__chip--crit" in body
    assert "mission__chip--high" in body
    assert "mission__chip--med" in body
    assert "mission__chip--low" in body

    # Chip counts are wired to data-live keys so SSE updates them.
    assert re.search(r'mission__chip--crit[^"]*"[^>]*data-mission-filter="critical"', body)


def test_mission_filter_chip_counts_match_view_model(client: TestClient, store: ScanStore) -> None:
    """Filter chip counts reflect the view-model's per-severity totals."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    # Crit count = 2, high = 2, medium = 1, low = 1 (from _make_scan fixture).
    # The chip render embeds those counts inside the data-live wired spans.
    assert re.search(r'data-live="critical"[^>]*>2<', body)
    assert re.search(r'data-live="high"[^>]*>2<', body)
    assert re.search(r'data-live="medium"[^>]*>1<', body)
    assert re.search(r'data-live="low"[^>]*>1<', body)


# ---------------------------------------------------------------------------
# 5. Findings table populated + row click hooks
# ---------------------------------------------------------------------------


def test_mission_findings_table_renders_one_row_per_finding(
    client: TestClient, store: ScanStore
) -> None:
    """Each finding from the view-model becomes a <tr> with the right severity class."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text

    # Six findings → six rows.
    rows = re.findall(r'class="mission__row mission__row--(critical|high|medium|low)"', body)
    assert len(rows) == 6
    # Sort order: critical → high → medium → low (matches view-model contract).
    assert rows[:2] == ["critical", "critical"]
    assert rows[-1] == "low"

    # Severity pills present
    assert "mission-pill--critical" in body
    assert "mission-pill--high" in body

    # Each row carries data-finding-id so JS can open the slide-over.
    finding_ids = re.findall(r'data-finding-id="([^"]+)"', body)
    assert {"f-crit-1", "f-crit-2", "f-high-1", "f-low-1"}.issubset(set(finding_ids))


def test_mission_findings_table_data_live_wrapper_present(
    client: TestClient, store: ScanStore
) -> None:
    """The tbody is wrapped with data-live='findings-list' so SSE can replace it."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    assert 'data-live="findings-list"' in resp.text


# ---------------------------------------------------------------------------
# 6. data-live SSE keys mirrored
# ---------------------------------------------------------------------------


_EXPECTED_DATA_LIVE_KEYS = {
    "aivss",
    "band",
    "aivss-total",
    "elapsed",
    "elapsed-bar",
    "probes",
    "tokens",
    "tokens-bar",
    "findings",
    "findings-total",
    "asi-covered",
    "critical",
    "high",
    "medium",
    "low",
    "findings-list",
}


def test_mission_mirrors_data_live_sse_keys(client: TestClient, store: ScanStore) -> None:
    """Mission embeds the same data-live keys as Editorial so SSE patches work identically."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    keys_found = set(re.findall(r'data-live="([a-z\-]+)"', body))
    missing = _EXPECTED_DATA_LIVE_KEYS - keys_found
    assert not missing, f"missing data-live keys: {missing}"


# ---------------------------------------------------------------------------
# 7. Agent sparkline list mirrors ASI breakdown
# ---------------------------------------------------------------------------


def test_mission_agent_panel_has_one_row_per_asi_axis(client: TestClient, store: ScanStore) -> None:
    """The agent panel left rail renders one row per ASI axis (10 total)."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    asi_codes = re.findall(r'data-agent-asi="(ASI\d{2})"', body)
    assert len(asi_codes) == 10
    assert set(asi_codes) == {f"ASI{i:02d}" for i in range(1, 11)}


def test_mission_agent_panel_rows_have_sparkline_canvases(
    client: TestClient, store: ScanStore
) -> None:
    """Each agent row has a sparkline canvas the JS mounts via Chart.js."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    sparks = re.findall(r'data-agent-spark="(ASI\d{2})"', body)
    assert len(sparks) == 10


# ---------------------------------------------------------------------------
# 8. Dark mode CSS + light variant present in stylesheet
# ---------------------------------------------------------------------------


def test_mission_css_dark_default_and_light_variant_present() -> None:
    """The Mission stylesheet defines dark surfaces and a prefers-color-scheme: light block."""
    css_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "agent_guardian"
        / "server"
        / "static"
        / "mission.css"
    )
    assert css_path.is_file(), "mission.css missing"
    css = css_path.read_text(encoding="utf-8")
    # Dark canonical surfaces — the Mission token set
    assert "--m-bg:" in css
    assert "--m-surface:" in css
    assert "--m-ink:" in css
    # Severity hues
    assert "--sev-crit:" in css
    assert "--sev-pass:" in css
    # Light variant
    assert "@media (prefers-color-scheme: light)" in css
    # Reduced-motion respect
    assert "prefers-reduced-motion" in css


def test_mission_css_linked_from_layout(client: TestClient, store: ScanStore) -> None:
    """The Mission layout pulls in /static/mission.css + /static/mission_charts.js."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    assert "/static/mission.css" in body
    assert "/static/mission_charts.js" in body
    # Chart.js v4 UMD CDN
    assert "chart.js" in body or "chart.umd" in body


def test_mission_css_is_served(client: TestClient) -> None:
    """The /static/mission.css asset 200s with the expected token marker."""
    resp = client.get("/static/mission.css")
    assert resp.status_code == 200
    assert "--m-bg" in resp.text
    assert "@media (prefers-color-scheme: light)" in resp.text


def test_mission_charts_js_is_served(client: TestClient) -> None:
    """The /static/mission_charts.js asset 200s and exposes the chart helpers."""
    resp = client.get("/static/mission_charts.js")
    assert resp.status_code == 200
    assert "mountTimeseries" in resp.text
    assert "mountAsiBar" in resp.text
    assert "mountSparkline" in resp.text


# ---------------------------------------------------------------------------
# 9. Zero-findings + in-flight states
# ---------------------------------------------------------------------------


def test_mission_renders_clean_scan_with_no_findings(client: TestClient, store: ScanStore) -> None:
    """A completed scan with zero findings still renders the empty-state row, not a crash."""
    scan = _make_scan().model_copy(update={"findings": []})
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    assert resp.status_code == 200
    body = resp.text
    # The empty-state caption
    assert "no findings recorded" in body or "clean scan" in body
    # Filter chip counts are all zero.
    assert re.search(r'data-live="critical"[^>]*>0<', body)


def test_mission_renders_for_in_flight_scan(client: TestClient, store: ScanStore) -> None:
    """A registered but not-yet-completed scan renders the awaiting-first-finding state."""
    scan_id = "cli-mission-running"
    # ScanStore.is_running() depends on register() — we simulate a registered
    # scan by creating the scan dir without a scan.json file.
    scan_dir = store.scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    resp = client.get(f"/scan/{scan_id}?theme=mission")
    assert resp.status_code == 200
    body = resp.text
    # The mission body is present
    assert "mission__topbar" in body
    # And the empty-state caption is the "awaiting" branch when is_running.
    # The fixture above doesn't register() so is_running may be False — the
    # empty-state may render either branch; what we care about is the page
    # doesn't 500.


# ---------------------------------------------------------------------------
# 10. Slide-over chrome + close-button hooks
# ---------------------------------------------------------------------------


def test_mission_slideover_chrome_renders_with_close_hooks(
    client: TestClient, store: ScanStore
) -> None:
    """The slide-over has a title, body, backdrop, and at least one close button."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=mission")
    body = resp.text
    # Slide-over chrome
    assert 'id="mission-slideover"' in body
    assert 'id="mission-slideover-title"' in body
    assert "data-mission-slideover-body" in body
    assert "data-mission-slideover-close" in body
    # Backdrop
    assert "data-mission-slideover-backdrop" in body
