"""Dashboard scan delete (#111) + failed/incomplete terminal status (#112)."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.scan_store import (
    STALE_RUNNING_AFTER_SECONDS,
    _derive_status,
)


def _seed(store: ScanStore, scan_id: str, **row: object) -> None:
    """Create the scan dir + one on-disk index row."""
    store.scan_dir(scan_id).mkdir(parents=True, exist_ok=True)
    idx = store._index_read()
    idx[scan_id] = {"scan_id": scan_id, **row}
    store._index_write(idx)


# --------------------------------------------------------------- #111 delete


def test_delete_scan_removes_dir_and_index_row(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    _seed(store, "cli-aaa", mtime=time.time(), aivss=80, band="Good", is_running=False)
    assert store.scan_dir("cli-aaa").is_dir()

    assert store.delete_scan("cli-aaa") is True
    assert not store.scan_dir("cli-aaa").exists()
    assert "cli-aaa" not in store._index_read()


def test_delete_scan_unknown_returns_false(tmp_path: Path) -> None:
    assert ScanStore(root_dir=tmp_path).delete_scan("cli-nope") is False


def test_delete_scan_rejects_traversal(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    for bad in ("../etc", "a/b", "/abs", "..", "x\x00y"):
        try:
            store.delete_scan(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} should have raised ValueError")


def test_delete_route_round_trip(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    _seed(store, "cli-route", mtime=time.time(), aivss=70, band="Warning", is_running=False)
    client = TestClient(create_app(scan_store=store))

    r = client.delete("/scan/cli-route")
    assert r.status_code == 200
    assert r.json()["deleted"] == "cli-route"
    assert not store.scan_dir("cli-route").exists()

    # Already gone → 404.
    second = client.delete("/scan/cli-route")
    assert second.status_code == 404


# --------------------------------------------------------------- #112 status


def test_derive_status_matrix() -> None:
    now = 1000.0
    fresh = now
    stale = now - STALE_RUNNING_AFTER_SECONDS - 1
    assert _derive_status(is_running=True, has_score=False, mtime=fresh, now=now) == "running"
    assert _derive_status(is_running=True, has_score=False, mtime=stale, now=now) == "failed"
    assert _derive_status(is_running=False, has_score=True, mtime=now, now=now) == "completed"
    assert _derive_status(is_running=False, has_score=False, mtime=now, now=now) == "failed"


def test_stale_running_listed_as_failed_with_suppressed_score(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    # Index says running, but the dir is ancient and a stale score is recorded —
    # the classic "stuck running / misleading number" case from #112.
    _seed(
        store,
        "cli-stuck",
        mtime=time.time() - STALE_RUNNING_AFTER_SECONDS - 60,
        aivss=42,
        band="Critical",
        findings_count=3,
        is_running=True,
    )
    page, _total = store.list_scans_page()
    row = next(s for s in page if s.scan_id == "cli-stuck")

    assert row.status == "failed"
    assert row.is_running is False
    # The stale numbers must NOT surface as a real-looking result.
    assert row.aivss is None
    assert row.band is None
    assert row.findings_count is None


def test_home_renders_status_and_delete_controls(tmp_path: Path) -> None:
    store = ScanStore(root_dir=tmp_path)
    _seed(
        store,
        "cli-good",
        mtime=time.time(),
        aivss=88,
        band="Good",
        findings_count=2,
        is_running=False,
    )
    _seed(
        store,
        "cli-stuck",
        mtime=time.time() - STALE_RUNNING_AFTER_SECONDS - 60,
        aivss=42,
        band="Critical",
        findings_count=9,
        is_running=True,
    )
    client = TestClient(create_app(scan_store=store))
    html = client.get("/").text

    # #111 — per-row delete control wired to the static handler.
    assert "btn-delete" in html
    assert 'data-scan-id="cli-good"' in html
    assert "/static/home.js" in html
    # #112 — the stuck scan shows a failed pill and does NOT leak its stale score.
    assert "pill-failed" in html
    assert ">42<" not in html
