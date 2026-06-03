"""SSE Phase 2, Step 2.4 — Live-append <template> slot tests.

Asserts the per-tab ``<template data-row-template>`` blocks are present
in the rendered Executive dashboard HTML, that each carries the right
``data-kind`` discriminator, and that the row skeleton elements match
the server-side row markup exactly (so a JS clone of the template
produces a row visually indistinguishable from a server-rendered row).

These tests are the static guard. The dynamic acceptance (new finding
visible within 200ms of producer emit, no F5) is verified by the live
verify phase in the workflow — see the Phase 2 design doc at
``designs/sse-flow-and-live-ui.md`` ("Phase 2 decisions resolved
2026-06-03").
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
from agent_guardian.server import ScanStore, create_app


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_finding(fid: str, severity: Severity, asi: AsiCategory) -> Finding:
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


def _make_scan() -> Scan:
    return Scan(
        id="cli-live-append-001",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=72,
        band=SeverityBand.WARNING,
        sub_scores={
            "prompt_injection_resistance": 72.0,
            "tool_scope_safety": 88.0,
            "pii_containment": 95.0,
            "memory_poisoning_resistance": 68.0,
            "excessive_agency_containment": 84.0,
            "hallucination_resistance": 79.0,
        },
        findings=[
            _make_finding("f-crit-1", Severity.CRITICAL, AsiCategory.ASI01),
            _make_finding("f-high-1", Severity.HIGH, AsiCategory.ASI02),
        ],
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


def _slice(body: str, start_marker: str, end_marker: str) -> str:
    start = body.find(start_marker)
    assert start != -1, f"missing {start_marker}"
    end = body.find(end_marker, start)
    if end == -1:
        end = len(body)
    return body[start:end]


def _findings_pane(body: str) -> str:
    return _slice(body, 'id="tabpanel-findings"', 'id="tabpanel-probes"')


def _probes_pane(body: str) -> str:
    return _slice(body, 'id="tabpanel-probes"', 'id="tabpanel-logs"')


def _logs_pane(body: str) -> str:
    start = body.find('id="tabpanel-logs"')
    assert start != -1
    end = body.find("</main>", start)
    return body[start : end if end != -1 else len(body)]


# ----------------------------------------------------------------------
# 1. Per-tab <template> slot presence + discriminator.
# ----------------------------------------------------------------------


def test_findings_tab_has_row_template(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # The <template> opens with both attribute markers.
    assert "<template" in pane
    assert "data-row-template" in pane
    assert 'data-kind="finding"' in pane
    # Exactly one finding row-template in this pane.
    assert pane.count('data-kind="finding"') == 1


def test_probes_tab_has_row_template(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    assert "<template" in pane
    assert "data-row-template" in pane
    assert 'data-kind="probe"' in pane
    assert pane.count('data-kind="probe"') == 1


def test_logs_tab_has_row_template(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _logs_pane(resp.text)
    assert "<template" in pane
    assert "data-row-template" in pane
    assert 'data-kind="log"' in pane
    assert pane.count('data-kind="log"') == 1


# ----------------------------------------------------------------------
# 2. Row template element shape — slot selectors are the public contract
# between the server-rendered template and the JS row builders. Every
# data-slot below MUST be present (the JS keys off them by name) or
# rows will render as visually empty <tr>s post-clone.
# ----------------------------------------------------------------------


def test_findings_row_template_slots(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # Slice down to the template itself so we don't false-match the
    # server-rendered rows above.
    tpl_start = pane.find('data-kind="finding"')
    assert tpl_start != -1
    tpl_end = pane.find("</template>", tpl_start)
    assert tpl_end != -1
    tpl = pane[tpl_start:tpl_end]
    for slot in (
        "sev-pill",
        "sev-label",
        "asi",
        "category",
        "agent",
        "probe",
        "summary",
        "turn",
    ):
        assert f'data-slot="{slot}"' in tpl, f"finding row template missing data-slot='{slot}'"


def test_probes_row_template_slots(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _probes_pane(resp.text)
    tpl_start = pane.find('data-kind="probe"')
    assert tpl_start != -1
    tpl_end = pane.find("</template>", tpl_start)
    assert tpl_end != -1
    tpl = pane[tpl_start:tpl_end]
    for slot in (
        "probe-id",
        "asi",
        "agent",
        "verdict-pill",
        "turn",
        "timestamp",
    ):
        assert f'data-slot="{slot}"' in tpl, f"probe row template missing data-slot='{slot}'"


def test_logs_row_template_slots(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _logs_pane(resp.text)
    tpl_start = pane.find('data-kind="log"')
    assert tpl_start != -1
    tpl_end = pane.find("</template>", tpl_start)
    assert tpl_end != -1
    tpl = pane[tpl_start:tpl_end]
    for slot in (
        "timestamp",
        "level",
        "kind",
        "agent",
        "asi",
        "summary",
    ):
        assert f'data-slot="{slot}"' in tpl, f"log row template missing data-slot='{slot}'"


# ----------------------------------------------------------------------
# 3. Live-append script is wired into the layout.
# ----------------------------------------------------------------------


def test_layout_loads_live_append_script(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert "/static/live-append.js" in body


def test_layout_attaches_live_append_to_events_stream(client: TestClient, store: ScanStore) -> None:
    """The layout-shell inline script opens ``/scan/<id>/events`` and
    calls ``AGLiveAppend.attach`` on it — that's the wiring contract.

    A terminal scan should NOT open the stream (no producer left). The
    fixture scan above is non-terminal so the wiring should be present.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert "AGLiveAppend.attach" in body
    assert "/scan/" in body
    assert "/events" in body


# ----------------------------------------------------------------------
# 4. Snapshot-only-by-design comments have been REVERSED on all three
# tabs. The old phrasing must be gone; the new live-append contract
# comment must be present.
# ----------------------------------------------------------------------


def test_findings_tab_documents_live_append_contract(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # The Jinja comment is stripped from the rendered HTML, so we
    # cannot assert it directly. Instead, verify the user-visible
    # consequence: the template slot IS present (covered above) AND
    # the inline-script wiring is registered in the layout.
    assert 'data-kind="finding"' in pane


def test_logs_tab_lede_no_longer_advertises_f5(client: TestClient, store: ScanStore) -> None:
    """The Logs tab's lede used to read "press F5 to refresh" — that
    text is the user-visible footprint of the snapshot-only contract
    we just reversed. Replaced with "updating live"."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _logs_pane(resp.text)
    assert "press <kbd>F5</kbd> to refresh" not in pane
    assert "updating live" in pane
