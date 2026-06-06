"""Route-level tests for the M12 dashboard FastAPI app.

We don't run a real server here — the FastAPI :class:`TestClient`
exercises each route in-process. The :class:`ScanStore` is pointed at
a temporary directory so the tests never touch the user's
``~/.agentguardian/scans``.
"""

from __future__ import annotations

import json
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
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
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
        # #4 — ``mode`` is required.
        mode="full",
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
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


def test_export_index_lists_raw_logs_and_probe_records(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    sd = store.scan_dir(scan.id)
    (sd / "run.log").write_text("hello log", encoding="utf-8")
    (sd / "events.jsonl").write_text('{"kind":"x"}\n', encoding="utf-8")
    (sd / "probe").mkdir()
    (sd / "probe" / "goal-hijack-agent.json").write_text('{"agent":"goal-hijack-agent"}', "utf-8")
    resp = client.get(f"/scan/{scan.id}/export")
    assert resp.status_code == 200
    assert "run.log" in resp.text
    assert "events.jsonl" in resp.text
    assert "goal-hijack-agent.json" in resp.text


def test_raw_download_serves_whitelisted_file(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    (store.scan_dir(scan.id) / "run.log").write_text("the full trace", encoding="utf-8")
    resp = client.get(f"/scan/{scan.id}/raw/run.log")
    assert resp.status_code == 200
    assert resp.text == "the full trace"


def test_raw_download_rejects_non_whitelisted(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    (store.scan_dir(scan.id) / "secrets.txt").write_text("nope", encoding="utf-8")
    resp = client.get(f"/scan/{scan.id}/raw/secrets.txt")
    assert resp.status_code == 400


def test_probe_file_download_and_traversal_guard(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    sd = store.scan_dir(scan.id)
    (sd / "probe").mkdir()
    (sd / "probe" / "tool-abuse-agent.json").write_text('{"agent":"tool-abuse-agent"}', "utf-8")
    ok = client.get(f"/scan/{scan.id}/probe-file/tool-abuse-agent.json")
    assert ok.status_code == 200
    assert json.loads(ok.text)["agent"] == "tool-abuse-agent"
    # Path traversal is reduced to a basename → never escapes probe/.
    bad = client.get(f"/scan/{scan.id}/probe-file/..%2F..%2Fscan.json")
    assert bad.status_code in (400, 404)


def test_export_bundle_zip_contains_reports_probes_and_raw(
    client: TestClient, store: ScanStore
) -> None:
    """``/export/bundle.zip`` streams ONE zip with reports + probes + raw logs."""
    import io
    import zipfile

    scan = _make_scan()
    _persist(store, scan)
    sd = store.scan_dir(scan.id)
    (sd / "run.log").write_text("the full trace", encoding="utf-8")
    (sd / "events.jsonl").write_text('{"kind":"x"}\n', encoding="utf-8")
    (sd / "probe").mkdir()
    (sd / "probe" / "tool-abuse-agent.json").write_text('{"agent":"tool-abuse-agent"}', "utf-8")

    resp = client.get(f"/scan/{scan.id}/export/bundle.zip")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert scan.id in resp.headers.get("content-disposition", "")

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = set(zf.namelist())
    # The canonical JSON report (always present via scan.json fallback).
    assert any(n.endswith(".json") and "report" in n for n in names) or "reports/json.json" in names
    # Raw artifacts land under raw/, probe records under probe/.
    assert "raw/run.log" in names
    assert "raw/events.jsonl" in names
    assert "probe/tool-abuse-agent.json" in names
    # Contents survive the round-trip.
    assert zf.read("raw/run.log").decode() == "the full trace"


def test_export_bundle_zip_404_for_unknown_scan(client: TestClient, store: ScanStore) -> None:
    resp = client.get("/scan/does-not-exist/export/bundle.zip")
    assert resp.status_code == 404


def test_export_index_links_bundle_zip(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/export")
    assert resp.status_code == 200
    assert f"/scan/{scan.id}/export/bundle.zip" in resp.text


def test_home_lists_completed_scans(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get("/")
    assert resp.status_code == 200
    assert scan.id in resp.text
    assert "WARNING" in resp.text


# ---------------------------------------------------------------------------
# Dashboard redaction (#3) — every finding surface must scrub PII/secrets
# ---------------------------------------------------------------------------


def _make_leaky_finding(fid: str = "f-leak") -> Finding:
    return Finding(
        id=fid,
        probe_id=f"probe-{fid}",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=2,
        success=True,
        confidence=0.91,
        summary="target leaked victim@example.com and key sk-proj-ABCDEF1234567890",
        transcript_ref="USER: my ssn is 123-45-6789",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
    )


def test_transcripts_view_redacts_by_default(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan(findings=[_make_leaky_finding()])
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/transcripts/f-leak")
    assert resp.status_code == 200
    # Raw PII / secrets must NOT reach the browser.
    assert "victim@example.com" not in resp.text
    assert "sk-proj-ABCDEF1234567890" not in resp.text
    assert "123-45-6789" not in resp.text
    # Redaction markers are present.
    assert "[REDACTED:" in resp.text
    # The "on" chip is shown when redaction is actually applied.
    assert "PII redaction: on" in resp.text


def test_transcripts_view_raw_when_redact_false(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan(findings=[_make_leaky_finding()])
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/transcripts/f-leak?redact=false")
    assert resp.status_code == 200
    # With redaction explicitly off, the raw text is shown (operator opt-in).
    assert "victim@example.com" in resp.text
    assert "off (raw)" in resp.text


def test_findings_view_redacts_summary(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan(findings=[_make_leaky_finding()])
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/findings")
    assert resp.status_code == 200
    assert "victim@example.com" not in resp.text
    assert "sk-proj-ABCDEF1234567890" not in resp.text
    assert "[REDACTED:" in resp.text


def test_coverage_view_redacts_summary(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan(findings=[_make_leaky_finding()])
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/coverage")
    assert resp.status_code == 200
    assert "victim@example.com" not in resp.text
    assert "sk-proj-ABCDEF1234567890" not in resp.text


# ---------------------------------------------------------------------------
# Branding (#24) — no "AgentGuardian Open"; no hardcoded localhost:7474
# ---------------------------------------------------------------------------


def test_coverage_view_has_no_forbidden_open_branding(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/coverage")
    assert resp.status_code == 200
    assert "AgentGuardian" in resp.text
    assert "<em>Open</em>" not in resp.text
    # The URL chip reflects the real request host, not a hardcoded :7474.
    assert ":7474" not in resp.text


def test_analytics_view_has_no_forbidden_open_branding(client: TestClient) -> None:
    resp = client.get("/analytics")
    assert resp.status_code == 200
    assert "<em>Open</em>" not in resp.text


def test_export_view_has_no_stale_m13_footnote(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/export")
    assert resp.status_code == 200
    assert "lands in M13" not in resp.text


# ---------------------------------------------------------------------------
# Telemetry-ingest WRITE endpoint protection (#11)
# ---------------------------------------------------------------------------


def test_ingest_loopback_client_not_forbidden(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A POST from the (loopback) TestClient is never 403 — at worst 422 on a
    bad body, but the auth gate lets it through."""
    monkeypatch.setenv("AGENT_GUARDIAN_ANALYTICS_DB", str(tmp_path / "a.db"))
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST", raising=False)
    resp = client.post("/api/telemetry/v1/events", json={"not": "an envelope"})
    assert resp.status_code != 403


def test_ingest_authorized_helper_blocks_remote_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from agent_guardian.server.routes.analytics import _ingest_authorized

    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST", raising=False)

    remote = SimpleNamespace(client=SimpleNamespace(host="203.0.113.7"), headers={})
    assert _ingest_authorized(remote) is False  # type: ignore[arg-type]

    local = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})
    assert _ingest_authorized(local) is True  # type: ignore[arg-type]


def test_ingest_authorized_helper_token_unlocks_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from agent_guardian.server.routes.analytics import _ingest_authorized

    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN", "s3cr3t")
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST", raising=False)

    good = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={"x-agentguardian-ingest-token": "s3cr3t"},
    )
    assert _ingest_authorized(good) is True  # type: ignore[arg-type]

    bad = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={"x-agentguardian-ingest-token": "wrong"},
    )
    assert _ingest_authorized(bad) is False  # type: ignore[arg-type]
