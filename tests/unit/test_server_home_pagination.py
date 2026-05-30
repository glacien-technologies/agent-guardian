"""Tests for /home pagination + scan_store cold-path index.

The launch-readiness audit flagged the unpaginated /home as a perf/UX bomb
when a user has thousands of scans on disk. These tests assert:

* /home accepts ?page= and ?page_size= query params.
* list_scans_page returns the correct slice and a stable total.
* The on-disk _index.json fast path is used when present.
* The cold path (no index) still works.
* The asyncio.to_thread wrapper round-trips identically.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
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
from agent_guardian.server.scan_store import INDEX_FILENAME


def _make_scan(scan_id: str, *, created_at: datetime) -> Scan:
    finding = Finding(
        id=f"{scan_id}-f-1",
        probe_id="probe-1",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success=False,
        confidence=0.5,
        summary="finding",
        created_at=created_at,
    )
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        mode="full",
        aivss=80,
        band=SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 90.0,
            "tool_scope_safety": 90.0,
            "pii_containment": 80.0,
            "memory_poisoning_resistance": 85.0,
            "excessive_agency_containment": 80.0,
            "hallucination_resistance": 85.0,
        },
        findings=[finding],
        asi_scores={cat: 90.0 for cat in AsiCategory},
        duration_seconds=4.2,
        cost_usd=0.0,
        created_at=created_at,
    )


def _persist(store: ScanStore, scan: Scan) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# list_scans_page — basic mechanics
# ---------------------------------------------------------------------------


def test_list_scans_page_returns_empty_when_no_scans(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    page, total = store.list_scans_page(offset=0, limit=10)
    assert page == []
    assert total == 0


def test_list_scans_page_paginates_completed_scans_newest_first(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    base = datetime(2026, 5, 30, 12, 0, 0, tzinfo=timezone.utc)
    # 25 scans, decreasing recency.
    for i in range(25):
        _persist(store, _make_scan(f"scan-{i:02d}", created_at=base - timedelta(hours=i)))

    page, total = store.list_scans_page(offset=0, limit=10)
    assert total == 25
    assert len(page) == 10
    # Newest first → scan-00.
    assert page[0].scan_id == "scan-00"
    assert page[-1].scan_id == "scan-09"

    page_2, _ = store.list_scans_page(offset=10, limit=10)
    assert [s.scan_id for s in page_2] == [f"scan-{i:02d}" for i in range(10, 20)]

    page_3, _ = store.list_scans_page(offset=20, limit=10)
    assert [s.scan_id for s in page_3] == [f"scan-{i:02d}" for i in range(20, 25)]


def test_list_scans_page_clamps_huge_limit(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    _persist(store, _make_scan("only-one", created_at=datetime.now(timezone.utc)))
    page, _ = store.list_scans_page(offset=0, limit=10_000)
    # Limit clamped to 500 — page still has the one row.
    assert len(page) == 1


def test_list_scans_page_clamps_negative_offset(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    _persist(store, _make_scan("scan-x", created_at=datetime.now(timezone.utc)))
    page, total = store.list_scans_page(offset=-5, limit=10)
    assert total == 1
    assert page[0].scan_id == "scan-x"


# ---------------------------------------------------------------------------
# Index fast path
# ---------------------------------------------------------------------------


def test_index_written_on_register(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    store.register("scan-idx", FakeSwarm())  # type: ignore[arg-type]
    index_path = tmp_path / INDEX_FILENAME
    assert index_path.is_file()
    raw = json.loads(index_path.read_text(encoding="utf-8"))
    assert "scan-idx" in raw
    assert raw["scan-idx"]["is_running"] is True


def test_index_updated_on_scan_done(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    from agent_guardian.core.swarm import SwarmEvent

    store = ScanStore(root_dir=tmp_path)

    class FakeSwarm:
        observer = None

    fake = FakeSwarm()
    store.register("scan-idx", fake)  # type: ignore[arg-type]
    # Persist a scan record so the index upsert can read it.
    _persist(store, _make_scan("scan-idx", created_at=datetime(2026, 5, 30, tzinfo=timezone.utc)))
    assert fake.observer is not None
    fake.observer(
        SwarmEvent(
            kind="scan_done",  # type: ignore[arg-type]
            timestamp=datetime(2026, 5, 30, tzinfo=timezone.utc),
        )
    )
    raw = json.loads((tmp_path / INDEX_FILENAME).read_text(encoding="utf-8"))
    row = raw["scan-idx"]
    assert row["is_running"] is False
    assert row["aivss"] == 80
    assert row["band"] == SeverityBand.GOOD.value
    assert row["findings_count"] == 1


def test_index_fast_path_used_when_present(tmp_path: Path) -> None:
    """A pre-existing _index.json drives the page render without per-scan reads."""
    store = ScanStore(root_dir=tmp_path)
    # Hand-write an index with rows that DON'T have scan.json on disk.
    # This proves the fast path is used (cold path would yield zero rows).
    index = {
        f"scan-{i:02d}": {
            "scan_id": f"scan-{i:02d}",
            "mtime": 1700000000.0 + i,
            "aivss": 80,
            "band": "GOOD",
            "target_ref": "ex",
            "target_mode": "prompt",
            "findings_count": 1,
            "created_at": (
                datetime(2026, 5, 30, tzinfo=timezone.utc) - timedelta(hours=i)
            ).isoformat(),
            "is_running": False,
        }
        for i in range(15)
    }
    (tmp_path / INDEX_FILENAME).write_text(json.dumps(index), encoding="utf-8")
    page, total = store.list_scans_page(offset=0, limit=5)
    assert total == 15
    assert len(page) == 5
    # Newest first.
    assert page[0].scan_id == "scan-00"


def test_index_malformed_json_falls_back_to_cold_path(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    (tmp_path / INDEX_FILENAME).write_text("not json", encoding="utf-8")
    _persist(store, _make_scan("scan-1", created_at=datetime(2026, 5, 30, tzinfo=timezone.utc)))
    page, total = store.list_scans_page(offset=0, limit=10)
    # Cold path still finds the on-disk scan.
    assert total == 1
    assert page[0].scan_id == "scan-1"


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------


def test_list_scans_page_async_returns_same_result(tmp_path: Path) -> None:
    async def _run() -> None:
        store = ScanStore(root_dir=tmp_path)
        base = datetime(2026, 5, 30, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(3):
            _persist(store, _make_scan(f"a-{i}", created_at=base - timedelta(hours=i)))
        sync_page, sync_total = store.list_scans_page(offset=0, limit=10)
        async_page, async_total = await store.list_scans_page_async(offset=0, limit=10)
        assert sync_total == async_total == 3
        assert [s.scan_id for s in sync_page] == [s.scan_id for s in async_page]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Running scans always lead
# ---------------------------------------------------------------------------


def test_running_scans_appear_first_in_page(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    # One completed scan.
    _persist(
        store,
        _make_scan("done-1", created_at=datetime(2026, 5, 30, tzinfo=timezone.utc)),
    )

    class FakeSwarm:
        observer = None

    store.register("running-1", FakeSwarm())  # type: ignore[arg-type]
    page, total = store.list_scans_page(offset=0, limit=10)
    assert total == 2
    assert page[0].scan_id == "running-1"
    assert page[0].is_running is True
    assert page[1].scan_id == "done-1"


# ---------------------------------------------------------------------------
# /home route — pagination query params
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def test_home_accepts_page_query_params(client: TestClient, store: ScanStore) -> None:
    base = datetime(2026, 5, 30, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(12):
        _persist(store, _make_scan(f"scan-{i:02d}", created_at=base - timedelta(hours=i)))

    resp = client.get("/?page=1&page_size=5")
    assert resp.status_code == 200
    # First page → newest five.
    assert "scan-00" in resp.text
    assert "scan-04" in resp.text
    assert "scan-05" not in resp.text

    resp = client.get("/?page=2&page_size=5")
    assert resp.status_code == 200
    assert "scan-05" in resp.text
    assert "scan-09" in resp.text


def test_home_404s_past_end(client: TestClient, store: ScanStore) -> None:
    _persist(
        store,
        _make_scan("only", created_at=datetime(2026, 5, 30, tzinfo=timezone.utc)),
    )
    resp = client.get("/?page=10&page_size=5")
    assert resp.status_code == 404


def test_home_rejects_bad_page_size(client: TestClient) -> None:
    # FastAPI's Query(ge=1, le=500) validation kicks in before our handler.
    resp = client.get("/?page=1&page_size=10000")
    assert resp.status_code == 422
    resp = client.get("/?page=0&page_size=10")
    assert resp.status_code == 422
