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
    # Per-agent grouping (2026-06-03) dropped the PROBE ID column — the row
    # is identified by its agent, so there's no ``probe-id`` slot any more.
    for slot in (
        "asi",
        "agent",
        # RUNS — turn count, now in the agent cell next to the ASI badge.
        "turn",
        "verdict-pill",
        # SUMMARY column (2026-06-06 rev2) — AI one-liner (or live reasoning
        # gloss); the evidence column folded into it.
        "summary",
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
    """The layout-shell inline script subscribes to the shared
    ``AGStreams.events`` source and calls ``AGLiveAppend.attach`` on
    it — that's the wiring contract.

    A terminal scan should NOT open the stream (no producer left). The
    fixture scan above is non-terminal so the wiring should be present.
    The actual URL ``/scan/<id>/events`` is constructed inside
    ``streams.js`` from ``data-scan-id`` so the inline boot script
    itself no longer mentions the path.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert "AGLiveAppend.attach" in body
    assert "AGStreams.events" in body
    assert "/static/streams.js" in body


def test_executive_modules_route_event_sources_through_agstreams() -> None:
    """Chrome's HTTP/1.1 per-origin connection cap is 6. When each live
    widget opened its own ``new EventSource(...)`` against the two
    pool-relevant endpoints (``/scan/<id>/events`` and
    ``/scans/<id>/live``), the page accumulated ~9 long-lived TCP
    connections and the overflow queued forever, starving the events
    stream. This test locks the consolidation contract: every executive
    module that opens those two endpoints must route through
    ``window.AGStreams``, not ``new EventSource`` directly.

    Exemptions:
        - ``streams.js`` — IS the shared cache; must call ``new EventSource``.
        - ``swarm.js`` — legacy swarm view, not loaded by the executive
          theme (no contribution to its connection pool).
        - ``reflections.js`` — different endpoint
          (``/scans/<id>/reflections.sse``) and a different uvicorn
          route; outside the events/live pool.
        - ``freshness-dot.js`` — only opens an EventSource when
          explicitly invoked to reconnect a wedged stream; not a
          standalone subscriber.
    """
    import re
    from pathlib import Path

    static_dir = (
        Path(__file__).resolve().parents[2] / "src" / "agent_guardian" / "server" / "static"
    )
    exempt = {"streams.js", "swarm.js", "reflections.js", "freshness-dot.js"}
    pool_endpoints = re.compile(r"['\"]/scans?/['\"]|/events|/live")
    new_es = re.compile(r"new\s+EventSource\s*\(")
    offenders: list[str] = []
    for js_path in static_dir.glob("*.js"):
        if js_path.name in exempt:
            continue
        source = js_path.read_text(encoding="utf-8")
        if new_es.search(source) and pool_endpoints.search(source):
            offenders.append(js_path.name)
    assert offenders == [], (
        "These executive modules still open EventSources against the pool "
        "endpoints directly instead of routing through `window.AGStreams`: " + ", ".join(offenders)
    )


def test_layout_loads_recon_live_script(client: TestClient, store: ScanStore) -> None:
    """#138 — recon-live.js owns a self-EventSource that re-fetches and
    swaps in ``#exec-recon`` when the ``recon_done`` event arrives. The
    layout shell must include the script so the module boots."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert "/static/recon-live.js" in body


def test_layout_snapshot_handler_logs_errors_not_swallow(
    client: TestClient, store: ScanStore
) -> None:
    """#138 — the snapshot-stream inline handler must NOT silently eat
    errors. Per-node patch failures and JSON parse failures both have to
    surface via ``console.error`` so a real regression is debuggable."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    # The exact silent-catch we used to ship.
    assert "catch (err) { /* swallow */ }" not in body
    # Both failure paths must log.
    assert "AGSnapshotStream: applyPatch failed" in body
    assert "AGSnapshotStream: snapshot frame parse failed" in body


def test_layout_snapshot_stream_uses_shared_source(client: TestClient, store: ScanStore) -> None:
    """The snapshot KPI patcher must subscribe to the shared
    ``AGStreams.snapshot`` source rather than opening its own
    EventSource. Without this consolidation the page accumulates 4+
    redundant snapshot connections (one per widget) and starves the
    HTTP/1.1 connection pool. The custom freshness watchdog that
    previously fronted ``new EventSource`` was dropped — the shared
    source relies on the browser's native EventSource auto-reconnect.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    assert "AGStreams.snapshot" in body
    assert "/static/streams.js" in body
    # The retired watchdog code must not have crept back in.
    assert "SNAPSHOT_STALE_MS" not in body
    assert "armWatchdog" not in body


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
    we just reversed.

    A COMPLETED scan's log tail is static, so the lede must NOT claim it
    is "updating live" (that misleads the operator); instead it offers a
    manual Refresh affordance. The "updating live" flag is reserved for
    in-flight (non-terminal) scans — see the running-scan test below."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _logs_pane(resp.text)
    assert "press <kbd>F5</kbd> to refresh" not in pane
    # Terminal scan: no false live claim, but a manual refresh control.
    assert "updating live" not in pane
    assert "data-logs-refresh" in pane


def test_logs_tab_lede_advertises_live_for_running_scan(
    client: TestClient, store: ScanStore
) -> None:
    """An in-flight scan's log tail DOES update live, so the lede keeps the
    "updating live" flag. A scan is in-flight when ``scan.partial.json`` is
    present on disk and no terminal ``scan.json`` has been written yet."""
    scan = _make_scan()
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    # Partial snapshot only (no terminal scan.json) → store.is_running == True.
    (scan_dir / "scan.partial.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _logs_pane(resp.text)
    assert "updating live" in pane
