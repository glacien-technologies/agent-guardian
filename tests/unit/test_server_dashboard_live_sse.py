"""Dashboard live SSE tests (QA-003).

The ``/scans/<id>/live`` endpoint streams ``snapshot`` events the page
mutates into the ``data-live=*`` nodes. The endpoint is poll-driven (reads
the store every 500ms) — these tests rely on TestClient's stream context
manager so we can yank the first event without waiting for the full poll
cycle.
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


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _make_scan(scan_id: str = "cli-live-test") -> Scan:
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
        findings=[
            Finding(
                id="f-1",
                probe_id="probe-1",
                asi=AsiCategory.ASI01,
                mitre_atlas=["AML.T0054"],
                csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
                severity=Severity.HIGH,
                attempt_count=2,
                success=True,
                confidence=0.9,
                summary="seed finding",
                created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
            )
        ],
        asi_scores={cat: 70.0 for cat in AsiCategory},
        duration_seconds=10.0,
        cost_usd=0.0,
        mode="full",
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=timezone.utc),
    )


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


def test_live_sse_emits_snapshot_for_completed_scan(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    with client.stream("GET", f"/scans/{scan.id}/live") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        first = next(resp.iter_lines())
        # The first non-empty line should announce the snapshot event.
        assert first.startswith("event: snapshot")


def test_live_sse_404_for_unknown_scan(client: TestClient) -> None:
    resp = client.get("/scans/nope/live")
    assert resp.status_code == 404


def test_live_sse_emits_scan_done_when_complete(client: TestClient, store: ScanStore) -> None:
    """For a completed scan, after the first snapshot we get a scan_done event."""
    scan = _make_scan()
    _persist(store, scan)
    with client.stream("GET", f"/scans/{scan.id}/live") as resp:
        # Drain lines until we see either 'event: scan_done' or the snapshot.
        # Bound the loop so a bug doesn't hang the test.
        kinds: list[str] = []
        for line in resp.iter_lines():
            if line.startswith("event:"):
                kinds.append(line)
            if "scan_done" in line:
                break
            if len(kinds) > 8:
                break
        assert any("scan_done" in k for k in kinds), kinds


def test_live_sse_keeps_streaming_for_running_scan(client: TestClient, store: ScanStore) -> None:
    """While a scan is registered as running, the stream emits the
    snapshot event and stays open (no scan_done until the scan completes).

    We use the live_snapshot view-model directly here rather than the full
    SSE stream because TestClient's stream context blocks on a long-poll
    loop that has no natural terminator for a running scan; the SSE format
    is exercised by the completed-scan tests above.
    """
    from agent_guardian.server.dashboard_view import (
        build_dashboard_context,
        live_snapshot,
    )

    scan_id = "cli-running-1"
    store.scan_dir(scan_id).mkdir(parents=True, exist_ok=True)
    try:
        ctx = build_dashboard_context(
            scan_id=scan_id,
            scan=None,
            is_running=True,
            base_url="http://127.0.0.1:7474",
            version_label=__version__,
            elapsed_seconds=5.0,
        )
        snap = live_snapshot(ctx)
        # Running snapshot still carries the data-live keys even with no
        # finalised scan; band is unknown/pending.
        assert snap["aivss"] == "—"
        assert snap["findings"] == 0
        assert "band" in snap
    finally:
        store._running.pop(scan_id, None)
