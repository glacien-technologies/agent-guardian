"""Route-level tests for the M12 dashboard FastAPI app.

We don't run a real server here — the FastAPI :class:`TestClient`
exercises each route in-process. The :class:`ScanStore` is pointed at
a temporary directory so the tests never touch the user's
``~/.agentguardian/scans``.
"""

from __future__ import annotations

import json
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


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_finding(fid: str = "f-1", asi: AsiCategory = AsiCategory.ASI01) -> Finding:
    return Finding(
        id=fid,
        probe_id=f"probe-{fid}",
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=2,
        success=True,
        confidence=0.91,
        summary=f"summary for {fid}",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_scan(scan_id: str = "scan-abc", findings: list[Finding] | None = None) -> Scan:
    findings = findings or [_make_finding("f-1"), _make_finding("f-2", AsiCategory.ASI02)]
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=72,
        band=SeverityBand.WARNING,
        sub_scores={
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 80.0,
            "pii_containment": 60.0,
            "memory_poisoning_resistance": 95.0,
            "excessive_agency_containment": 50.0,
            "hallucination_resistance": 75.0,
        },
        findings=findings,
        asi_scores={cat: 75.0 for cat in AsiCategory},
        duration_seconds=12.5,
        cost_usd=0.0,
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=timezone.utc),
    )


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


def test_create_app_returns_fastapi() -> None:
    from fastapi import FastAPI

    app = create_app()
    assert isinstance(app, FastAPI)
    assert app.title == "AgentGuardian"
    assert app.version == __version__


def test_home_renders_empty_history(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Scan history" in resp.text
    assert "No scans yet" in resp.text
    assert resp.headers["content-type"].startswith("text/html")


def test_about_renders(client: TestClient) -> None:
    resp = client.get("/about")
    assert resp.status_code == 200
    assert "About AgentGuardian" in resp.text
    assert __version__ in resp.text


def test_static_styles_served_with_css_mime(client: TestClient) -> None:
    resp = client.get("/static/styles.css")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    body = resp.text
    # Sanity check: the file is hand-authored CSS — look for known tokens.
    assert "--accent: #22d3ee" in body or "--accent:#22d3ee" in body
    # Light-mode override is present.
    assert "prefers-color-scheme: light" in body


def test_static_js_served_as_javascript(client: TestClient) -> None:
    resp = client.get("/static/app.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    body = resp.text
    # ES module — import statement is the entry indicator.
    assert "import" in body
    assert "mountScanView" in body


def test_static_swarm_and_charts_modules(client: TestClient) -> None:
    for name in ("swarm.js", "charts.js"):
        resp = client.get(f"/static/{name}")
        assert resp.status_code == 200, name
        assert "export" in resp.text, name


# ---------------------------------------------------------------------------
# Scan view + per-scan routes
# ---------------------------------------------------------------------------


def test_scan_view_404_for_unknown(client: TestClient) -> None:
    resp = client.get("/scan/does-not-exist")
    assert resp.status_code == 404


def test_scan_view_renders_completed_scan(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    assert scan.id in resp.text
    assert "AIVSS" in resp.text


def test_findings_view_lists_findings(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/findings")
    assert resp.status_code == 200
    assert "f-1" in resp.text
    assert "f-2" in resp.text


def test_findings_view_filters_by_asi(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/findings?asi=ASI02")
    assert resp.status_code == 200
    assert "f-2" in resp.text
    assert "f-1" not in resp.text


def test_findings_view_rejects_unknown_asi(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/findings?asi=ASI99")
    assert resp.status_code == 400


def test_aivss_view_renders_sub_scores(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/aivss")
    assert resp.status_code == 200
    assert "Sub-scores" in resp.text
    assert "prompt injection resistance" in resp.text


def test_swarm_view_renders_eleven_satellites(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/swarm")
    assert resp.status_code == 200
    # Eleven `data-slot` satellites in the SVG.
    assert resp.text.count("data-slot=") == 11


def test_transcripts_view_renders_known_finding(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/transcripts/f-1")
    assert resp.status_code == 200
    assert "Transcript" in resp.text
    assert "f-1" in resp.text


def test_transcripts_view_404_for_unknown_finding(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/transcripts/missing-id")
    assert resp.status_code == 404


def test_export_index_renders_format_links(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    # Write a couple of pretend report files.
    (store.scan_dir(scan.id) / "report.sarif").write_text("{}", encoding="utf-8")
    (store.scan_dir(scan.id) / "report.junit").write_text("<x/>", encoding="utf-8")
    resp = client.get(f"/scan/{scan.id}/export")
    assert resp.status_code == 200
    assert "/sarif" in resp.text or "report.sarif" in resp.text


def test_export_download_serves_file(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    # scan.json always counts as json export fallback.
    resp = client.get(f"/scan/{scan.id}/export/json")
    assert resp.status_code == 200
    body = json.loads(resp.text)
    assert body["id"] == scan.id


def test_export_download_rejects_unknown_format(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/export/xls")
    assert resp.status_code == 400


def test_export_download_404_when_report_missing(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    # SARIF was never written.
    resp = client.get(f"/scan/{scan.id}/export/sarif")
    assert resp.status_code == 404


def test_home_lists_completed_scans(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get("/")
    assert resp.status_code == 200
    assert scan.id in resp.text
    assert "WARNING" in resp.text
