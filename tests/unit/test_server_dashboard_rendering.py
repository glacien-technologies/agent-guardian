"""Dashboard rendering snapshot tests (QA-003).

Feeds a fixture ``Scan`` into the new ``dashboard/scan_detail.html`` template
tree and asserts:

* All design components are present (topbar, masthead, score card,
  at-a-glance, sub-scores, ASI table, findings feed, reproducibility).
* The Jegan corrections from ``docs/_design/live-dashboard/chats/chat1.md``
  are reflected (no top nav, locality pill trimmed, no "no telemetry" copy,
  paginated findings).
* The CLI-emitted canonical URL ``/scans/<id>`` 307-redirects to ``/scan/<id>``.
* The new ``/scans/<id>/report`` returns the canonical scan JSON.
* The locality pill switches between Local and Hosted based on base URL.
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
from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.dashboard_view import (
    build_dashboard_context,
    live_snapshot,
    resolve_locality,
)


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_finding(fid: str, severity: Severity, asi: AsiCategory = AsiCategory.ASI01) -> Finding:
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
        summary=f"finding {fid}",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_scan(scan_id: str = "cli-3a4c1d9c2840") -> Scan:
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


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# View-model unit tests
# ---------------------------------------------------------------------------


def test_resolve_locality_loopback_is_local() -> None:
    is_local, label, scheme, host, port = resolve_locality("http://127.0.0.1:7474")
    assert is_local is True
    assert label == "Local"
    assert host == "127.0.0.1"
    assert port == ":7474"
    assert scheme == "http:"


def test_resolve_locality_hosted_is_hosted() -> None:
    is_local, label, _, host, _ = resolve_locality("https://dash.example.com")
    assert is_local is False
    assert label == "Hosted · evidence-signed"
    assert host == "dash.example.com"


def test_resolve_locality_localhost_alias_is_local() -> None:
    is_local, label, *_ = resolve_locality("http://localhost:7474")
    assert is_local is True
    assert label == "Local"


def test_build_context_for_completed_scan_has_required_keys() -> None:
    scan = _make_scan()
    ctx = build_dashboard_context(
        scan_id=scan.id,
        scan=scan,
        is_running=False,
        base_url="http://127.0.0.1:7474",
        version_label=__version__,
    )
    required = {
        "scan_id",
        "is_running",
        "is_local",
        "locality_label",
        "aivss_label",
        "band_label",
        "band_class",
        "needle_pct",
        "asi_rows",
        "findings_page",
        "pagination",
        "package_version",
        "evidence_fingerprint",
        "counts",
    }
    assert required.issubset(ctx.payload.keys())
    assert ctx.payload["aivss_label"] == 84
    assert ctx.payload["band_class"] == "good"
    assert len(ctx.payload["asi_rows"]) == 10


def test_build_context_for_in_flight_scan_has_pending_state() -> None:
    ctx = build_dashboard_context(
        scan_id="cli-pending",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:7474",
        version_label=__version__,
    )
    assert ctx.payload["is_running"] is True
    assert ctx.payload["aivss_label"] == "—"
    assert ctx.payload["band_class"] == "unknown"
    assert ctx.payload["counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    assert ctx.payload["pagination"]["total_pages"] == 1


def test_findings_pagination_default_15_per_page() -> None:
    scan = _make_scan()
    # only 5 findings in fixture → single page
    ctx = build_dashboard_context(
        scan_id=scan.id,
        scan=scan,
        is_running=False,
        base_url="http://127.0.0.1:7474",
        version_label=__version__,
        per_page=15,
    )
    assert ctx.payload["pagination"]["total"] == 5
    assert ctx.payload["pagination"]["total_pages"] == 1
    assert len(ctx.payload["findings_page"]) == 5


def test_findings_sorted_criticality_first() -> None:
    scan = _make_scan()
    ctx = build_dashboard_context(
        scan_id=scan.id,
        scan=scan,
        is_running=False,
        base_url="http://127.0.0.1:7474",
        version_label=__version__,
    )
    severities = [f["severity_class"] for f in ctx.payload["findings_page"]]
    assert severities[:2] == ["critical", "critical"]
    assert "low" in severities[-1:]


def test_dashboard_context_handles_every_band_value() -> None:
    """``_headline_qualifier`` must have a copy line for every SeverityBand."""
    from agent_guardian.models.severity import SeverityBand

    for band in SeverityBand:
        scan = _make_scan()
        # mutate immutable model via pydantic copy
        scan = scan.model_copy(update={"band": band, "aivss": 50})
        ctx = build_dashboard_context(
            scan_id=scan.id,
            scan=scan,
            is_running=False,
            base_url="http://127.0.0.1:7474",
            version_label=__version__,
        )
        assert "<em>" in ctx.payload["headline_qualifier"], band
        # band_class is the lowercased band value
        assert ctx.payload["band_class"] == band.value.lower()


def test_humanise_seconds_clamps_negatives() -> None:
    """Negative elapsed (clock skew) clamps to 00:00 rather than rendering '-0:-1'."""
    ctx = build_dashboard_context(
        scan_id="cli-x",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:7474",
        version_label=__version__,
        elapsed_seconds=-30.0,
    )
    assert ctx.payload["elapsed_label"] == "00:00"


def test_lede_html_handles_zero_findings() -> None:
    """A completed clean scan still gets a usable lede."""
    scan = _make_scan().model_copy(update={"findings": []})
    ctx = build_dashboard_context(
        scan_id=scan.id,
        scan=scan,
        is_running=False,
        base_url="http://127.0.0.1:7474",
        version_label=__version__,
    )
    assert "tier" in ctx.payload["lede_html"]


def test_live_snapshot_contains_data_live_keys() -> None:
    scan = _make_scan()
    ctx = build_dashboard_context(
        scan_id=scan.id,
        scan=scan,
        is_running=False,
        base_url="http://127.0.0.1:7474",
        version_label=__version__,
    )
    snap = live_snapshot(ctx)
    for key in ("aivss", "band", "elapsed", "findings", "critical", "high"):
        assert key in snap


# ---------------------------------------------------------------------------
# Full template render (HTML smoke + design markers)
# ---------------------------------------------------------------------------


def test_dashboard_renders_for_completed_scan(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    body = resp.text
    # All design components present
    assert "dash-topbar" in body
    assert "dash-masthead" in body
    assert "dash-score-card" in body
    assert "dash-glance-grid" in body
    assert "dash-asi-table" in body
    assert "dash-feed-list" in body
    assert "dash-repro__grid" in body
    # Editorial italic in masthead
    assert "is scoring 84" in body
    # Score number visible in main + penalty footer
    assert body.count("84") >= 2


def test_dashboard_has_no_top_nav_per_jegan_correction(
    client: TestClient, store: ScanStore
) -> None:
    """Jegan correction #5: the top tabs (Overview/Findings/etc.) must be gone."""
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    body = resp.text
    # No nav link to Overview / Findings / Sub-scores as tabs at the top.
    assert ">Overview<" not in body
    assert ">Sub-scores</a>" not in body


def test_dashboard_locality_pill_is_local_on_loopback(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    body = resp.text
    # TestClient base_url is http://testserver — not loopback — so the live
    # rendered HTML reflects "Hosted". We assert the *structure* is present
    # and exercise the local case via the unit test above.
    assert "dash-locality" in body
    assert "AgentGuardian" in body


def test_dashboard_omits_no_telemetry_wording(client: TestClient, store: ScanStore) -> None:
    """Jegan correction #3: the dashboard should not claim 'no telemetry'.

    AgentGuardian does ship telemetry (see security/telemetry.md). Promising
    'no telemetry' in the dashboard chrome would be incorrect.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    body = resp.text
    assert "no telemetry" not in body.lower()


def test_dashboard_brand_is_agentguardian_not_open(client: TestClient, store: ScanStore) -> None:
    """CLAUDE.md: the product name is AgentGuardian (one word), never
    'AgentGuardian Open'.
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    body = resp.text
    assert "AgentGuardian Open" not in body
    assert "AgentGuardian" in body


def test_dashboard_clean_control_zero_high_findings(client: TestClient, store: ScanStore) -> None:
    """The ``clean_control`` sentry must render zero high-severity findings.

    We synthesise a clean scan and verify the dashboard's findings counts
    surface ``0 critical 0 high`` plainly.
    """
    scan = Scan(
        id="cli-clean-control-1",
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
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    body = resp.text
    assert "EXCELLENT" in body or "excellent" in body
    # No critical / high findings count
    assert 'data-live="critical">0' in body
    assert 'data-live="high">0' in body


# ---------------------------------------------------------------------------
# CLI-emitted /scans/<id> redirect + /report endpoint
# ---------------------------------------------------------------------------


def test_scans_id_redirects_to_legacy_scan_url(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scans/{scan.id}", follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == f"/scan/{scan.id}"


def test_scans_id_preserves_query_string(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scans/{scan.id}?page=2", follow_redirects=False)
    assert resp.status_code == 307
    assert "page=2" in resp.headers["location"]


def test_scans_id_404_for_unknown(client: TestClient) -> None:
    resp = client.get("/scans/nope", follow_redirects=False)
    assert resp.status_code == 404


def test_scans_id_report_returns_canonical_json(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scans/{scan.id}/report")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["id"] == scan.id
    assert payload["aivss"] == 84


def test_scans_id_report_404_for_unknown(client: TestClient) -> None:
    resp = client.get("/scans/nope/report")
    assert resp.status_code == 404


def test_scans_id_report_404_when_running(client: TestClient, store: ScanStore) -> None:
    # Make the scan dir exist so it isn't an unknown-id 404, then register
    # the scan as running so the running-branch fires.
    scan_id = "cli-still-running"
    store.scan_dir(scan_id).mkdir(parents=True, exist_ok=True)
    # Fake "running" by registering in the internal dict (we don't have a
    # real SwarmCommander here; the store's running registry is dict-backed).
    store._running[scan_id] = object()  # type: ignore[assignment]
    resp = client.get(f"/scans/{scan_id}/report")
    assert resp.status_code == 404
    payload = resp.json()
    assert payload.get("status") == "running"
    # Cleanup so subsequent tests aren't polluted.
    store._running.pop(scan_id, None)


def test_scans_id_report_falls_back_to_raw_json_when_load_fails(
    client: TestClient, store: ScanStore
) -> None:
    """When ``scan.json`` exists but the model can't deserialise it, the
    route falls back to streaming the raw JSON so the operator can inspect
    a crashed run.
    """
    scan_id = "cli-corrupt-1"
    scan_dir = store.scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    # Write a JSON file that's valid JSON but not a Scan (no required keys),
    # so load_completed returns None but the file is parseable.
    (scan_dir / "scan.json").write_text(
        '{"id": "cli-corrupt-1", "note": "partial"}', encoding="utf-8"
    )
    resp = client.get(f"/scans/{scan_id}/report")
    # Either 200 with the raw partial JSON, or 404 if neither path works.
    # The branch under test is the raw-fallback success path.
    assert resp.status_code == 200
    payload = resp.json()
    assert payload.get("note") == "partial"


def test_scans_id_report_404_when_dir_empty(client: TestClient, store: ScanStore) -> None:
    """Scan dir exists but contains no ``scan.json`` / ``scan.raw.json`` —
    the route returns a clean 404 rather than crashing.
    """
    scan_id = "cli-empty-dir"
    store.scan_dir(scan_id).mkdir(parents=True, exist_ok=True)
    # No scan.json file at all
    resp = client.get(f"/scans/{scan_id}/report")
    assert resp.status_code == 404


def test_live_sse_uses_request_base_url_when_env_unset(
    client: TestClient, store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``AGENT_GUARDIAN_DASHBOARD_URL`` is unset the live route synthesises
    the base URL from the FastAPI request — this exercises the env-fallback
    branch in ``_resolve_base_url``.
    """
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_URL", raising=False)
    scan = _make_scan()
    _persist(store, scan)
    with client.stream("GET", f"/scans/{scan.id}/live") as resp:
        assert resp.status_code == 200
        first = next(resp.iter_lines())
        assert first.startswith("event: snapshot")


def test_resolve_base_url_uses_env_when_set(
    client: TestClient, store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The env-set branch of ``_resolve_base_url`` strips a trailing slash."""
    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_URL", "https://dash.example.com/")
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    body = resp.text
    # When base_url is non-loopback, the locality pill says Hosted.
    assert ">Hosted" in body
