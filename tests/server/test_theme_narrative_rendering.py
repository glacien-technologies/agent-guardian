"""Narrative Report theme (Theme C) rendering snapshot tests.

The Narrative theme is the Stripe-Press / Linear-changelog interactive
report. These tests feed a fixture ``Scan`` through ``?theme=narrative``
and assert:

* The shell renders (topbar, TOC, masthead, sections, footer).
* The italic-serif headline + lede paragraph are present.
* The collapsible ``<details>`` sections each carry a stable anchor id.
* The Chart.js radar (FIG. 1) and severity bar (FIG. 2) canvases are
  present with their ``data-chart`` JSON payloads.
* Each finding renders as a card with header pill + headline + evidence
  trail nested toggles.
* The reproducibility receipt + footnotes anchor the page bottom.
* Every editorial ``data-live`` SSE key has a mirror node in the
  Narrative layout (so the existing live patcher works unchanged).
* A 0-findings clean scan still renders an empty-state, the receipt,
  and both chart canvases (radar still draws coverage; bar shows zeros).
"""

from __future__ import annotations

import re
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
        mitre_atlas=["AML.T0054", "AML.T0040"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=2,
        success=True,
        confidence=0.91,
        summary=f"Narrative-fixture finding {fid}: the agent leaked sensitive context.",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_scan(scan_id: str = "cli-narrative-fixture") -> Scan:
    findings = [
        _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
        _make_finding("f-crit-2", Severity.CRITICAL, AsiCategory.ASI06),
        _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
        _make_finding("f-med-1", Severity.MEDIUM, AsiCategory.ASI03),
        _make_finding("f-low-1", Severity.LOW, AsiCategory.ASI09),
    ]
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="http",
        target_ref="https://finbot.example.com/chat",
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


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_narrative_theme_renders_for_completed_scan(client: TestClient, store: ScanStore) -> None:
    """The full Narrative layout renders with status 200 and the chrome.

    Asserts every top-level structural block: topbar, TOC, headline,
    overview tile strip, every section anchor id, footer.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    assert resp.status_code == 200
    body = resp.text

    # Body marker + theme attr — Narrative layout boots
    assert 'class="nr-body"' in body
    assert 'data-theme="narrative"' in body

    # Topbar chrome
    assert "nr-topbar" in body
    assert "AgentGuardian" in body
    assert "Narrative Report" in body
    assert "nr-topbar__scan-pill" in body

    # Theme switcher partial included
    assert 'id="ag-theme-switcher-select"' in body
    assert 'data-current="narrative"' in body

    # TOC + main shell
    assert "nr-shell" in body
    assert "nr-shell__toc" in body
    assert "nr-shell__main" in body
    assert 'id="nr-main"' in body

    # Masthead structure (eyebrow, italic-serif headline, byline, lede)
    assert "nr-masthead" in body
    assert "nr-masthead__eyebrow" in body
    assert "nr-masthead__headline" in body
    assert "nr-masthead__byline" in body
    assert "nr-masthead__lede" in body
    assert "SCAN REPORT" in body

    # Overview tile strip with score / findings / asi / duration
    assert 'id="nr-section-overview"' in body
    assert "nr-overview__grid" in body

    # All collapsible section anchors must exist
    for anchor in (
        "nr-section-recon",
        "nr-section-asi",
        "nr-section-attacks",
        "nr-section-findings",
        "nr-section-reproducibility",
    ):
        assert f'id="{anchor}"' in body, f"missing section anchor: {anchor}"

    # Footer
    assert "nr-footer" in body
    assert f"v{__version__}" in body

    # Cross-theme locked findings heading (QA-023): every theme renders the
    # verbatim string "All findings so far." in its findings region.
    assert "All findings so far." in body


def test_narrative_charts_radar_and_bar_canvases_present(
    client: TestClient, store: ScanStore
) -> None:
    """Both inline Chart.js canvases are emitted with non-empty JSON payloads.

    The radar carries one value per ASI category; the severity bar carries
    one row per severity (critical / high / medium / low).
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    body = resp.text

    # Radar canvas + JSON payload
    radar_match = re.search(
        r'<canvas id="nr-asi-radar"[^>]*data-chart=\'([^\']+)\'',
        body,
    )
    assert radar_match is not None, "radar canvas with data-chart not found"
    radar_json = radar_match.group(1)
    assert '"labels"' in radar_json
    assert '"values"' in radar_json
    # Radar must have one entry per visible ASI row.
    assert radar_json.count("Goal hijack") >= 1

    # Severity bar canvas + JSON payload
    bar_match = re.search(
        r'<canvas id="nr-severity-bar"[^>]*data-chart=\'([^\']+)\'',
        body,
    )
    assert bar_match is not None, "severity bar canvas with data-chart not found"
    bar_json = bar_match.group(1)
    assert '"rows"' in bar_json
    assert "critical" in bar_json
    assert "high" in bar_json

    # Chart.js script include + theme charts script include
    assert "chart.umd.min.js" in body
    assert "narrative_charts.js" in body


def test_narrative_findings_render_each_as_a_card(client: TestClient, store: ScanStore) -> None:
    """Every finding appears as a card with header pill + headline + evidence."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    body = resp.text

    # Each fixture finding gets a card with a stable anchor id.
    for fid in ("f-crit-1", "f-crit-2", "f-high-1", "f-med-1", "f-low-1"):
        assert f'id="nr-finding-{fid}"' in body, f"missing card for {fid}"

    # Severity buckets are grouped by sev anchor (matches bar onClick handler)
    assert 'id="nr-sev-critical"' in body
    assert 'id="nr-sev-high"' in body

    # Severity pills are present
    assert "nr-sev-pill--critical" in body
    assert "nr-sev-pill--high" in body
    assert "nr-sev-pill--medium" in body
    assert "nr-sev-pill--low" in body

    # Evidence trail nested <details> per finding
    assert "nr-finding__evidence" in body
    assert "Evidence trail" in body

    # Cross-theme deep-links (the unique drill-down differentiator)
    assert "?theme=mission" in body
    assert "?theme=executive" in body


def test_narrative_data_live_keys_mirrored(client: TestClient, store: ScanStore) -> None:
    """Every Editorial data-live key has a mirror in the Narrative layout.

    The shared /scans/<id>/live SSE patcher must keep Narrative in sync
    without theme-specific code — confirmed by asserting every key in
    ``live_snapshot`` is present as a ``data-live`` attribute in the
    rendered Narrative HTML.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    body = resp.text

    required_live_keys = {
        "aivss",
        "band",
        "needle",
        "aivss-total",
        "elapsed",
        "elapsed-bar",
        "probes",
        "probes-bar",
        "tokens",
        "tokens-bar",
        "usd",
        "usd-bar",
        "findings",
        "findings-total",
        "asi-covered",
        "critical",
        "high",
        "medium",
        "low",
    }
    for key in required_live_keys:
        assert f'data-live="{key}"' in body, f"missing data-live mirror: {key}"


def test_narrative_reproducibility_receipt_and_footnotes_present(
    client: TestClient, store: ScanStore
) -> None:
    """The page closes with the receipt + numbered references list."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    body = resp.text

    # Reproducibility callout block
    assert "nr-callout" in body
    assert "REPRODUCIBILITY" in body
    assert "scan_id" in body
    assert "evidence" in body
    # Receipt mentions the scan id
    assert scan.id in body
    # Copy button is wired
    assert "nr-callout__copy" in body
    assert 'data-copy-target="#nr-repro-command"' in body

    # Footnotes / references list
    assert "nr-footnotes" in body
    assert "References" in body
    assert "OWASP" in body
    assert "MITRE ATLAS" in body


def test_narrative_clean_scan_renders_empty_state_and_charts(
    client: TestClient, store: ScanStore
) -> None:
    """A 0-findings clean scan still renders the empty-state + both charts.

    AC-5: the ``clean_control`` sentry must produce no false-positive
    surface. The Narrative theme handles this by:
      * Headline pivots to a "held clean" framing.
      * Findings section shows an empty-state lede instead of zero cards.
      * Both inline charts still render (radar shows coverage, bar shows
        zero counts).
      * The reproducibility receipt is unchanged.
    """
    scan = Scan(
        id="cli-narrative-clean",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="http",
        target_ref="https://clean.example.com",
        tier=Tier.T4_LOW,
        aivss=100,
        band=SeverityBand.EXCELLENT,
        sub_scores={
            "prompt_injection_resistance": 100.0,
            "tool_scope_safety": 100.0,
            "pii_containment": 100.0,
            "memory_poisoning_resistance": 100.0,
            "excessive_agency_containment": 100.0,
            "hallucination_resistance": 100.0,
        },
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=120.0,
        cost_usd=0.01,
        mode="full",
        created_at=datetime(2026, 5, 28, 12, 0, 0, tzinfo=timezone.utc),
    )
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    assert resp.status_code == 200
    body = resp.text

    # Empty-state lede instead of finding cards.
    assert "nr-empty-state" in body
    assert "No findings surfaced" in body or "still landing probes" in body

    # Both charts still ship.
    assert 'id="nr-asi-radar"' in body
    assert 'id="nr-severity-bar"' in body

    # Reproducibility receipt is preserved.
    assert "REPRODUCIBILITY" in body
    assert scan.id in body

    # Zero counts are visible in the overview strip.
    assert 'data-live="critical">0' in body
    assert 'data-live="high">0' in body


def test_narrative_theme_switcher_includes_all_four_themes(
    client: TestClient, store: ScanStore
) -> None:
    """The dropdown lists all four theme slugs with Narrative pre-selected."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    body = resp.text

    # Switcher dropdown is present and Narrative is current.
    assert 'id="ag-theme-switcher-select"' in body
    assert 'data-current="narrative"' in body

    # All four theme slugs appear as <option value="..."> entries.
    for slug in ("editorial", "mission", "narrative", "executive"):
        assert f'value="{slug}"' in body, f"theme option missing: {slug}"

    # Narrative is the one marked selected.
    selected_match = re.search(
        r'<option value="narrative"[^>]*\sselected[^>]*>',
        body,
    )
    assert selected_match is not None, "Narrative option not marked selected"


def test_narrative_toc_lists_every_section(client: TestClient, store: ScanStore) -> None:
    """The sticky TOC has one entry per main section, with severity dots
    on sections that contain critical findings.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=narrative")
    body = resp.text

    # TOC chrome.
    assert "nr-toc" in body
    assert "ON THIS PAGE" in body

    # One TOC link per section anchor.
    for target in (
        "nr-section-overview",
        "nr-section-asi",
        "nr-section-attacks",
        "nr-section-findings",
        "nr-section-recon",
        "nr-section-reproducibility",
    ):
        assert f'data-toc-target="{target}"' in body, f"missing TOC link: {target}"

    # Severity-dot appears when the section has critical findings.
    # The fixture has 2 critical, so the findings + attacks sections
    # should each get a critical dot.
    assert "nr-toc__dot--critical" in body
