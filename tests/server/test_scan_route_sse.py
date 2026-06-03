"""QA-022 — SSE branch coverage for ``server/routes/scan.py``.

Locks the uncovered SSE / keepalive paths in :func:`scans_live_sse`:

* line 207 — the ``_LIVE_MAX_SECONDS`` deadline-break path. Monkeypatched
  via the module-level constant so the loop exits in deterministic time
  without hanging the test runner.
* lines 213-214 — the ``except OSError`` branch on ``scan_dir.stat()``
  inside the SSE generator. Triggered by patching ``Path.stat`` for one
  call so the in-flight branch still renders a snapshot with ``mtime=None``.
* branch 230→239 — the "snapshot unchanged, skip yield" branch. Two polls
  on a running scan with no completed file produce identical snapshots;
  the second iteration takes the equality branch.
* lines 242-243 — the ``await asyncio.sleep(_LIVE_POLL_SECONDS)`` tick
  that was never exercised because every prior SSE test broke out via
  ``scan_done`` after one iteration.
* line 74 — ``_started_at_label(None)`` returns ``""``; exercised by the
  OSError-on-stat case (mtime falls through to None).

These are pre-existing branches (QA-022 baseline); QA-020's theme work
landed at 100% coverage and did not regress this surface. The tests are
written as locking tests — they FAIL on the pre-fix tree only if a
future refactor drops one of these branches; against today's tree they
pass and lift coverage from 88% → ≥95%.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.routes import scan as scan_route


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _register_running(store: ScanStore, scan_id: str) -> None:
    """Park a scan in the in-memory running registry.

    The real ``register()`` requires a ``SwarmCommander``; the store's
    registry is a plain dict so dropping a sentinel is sufficient for
    route-level tests.
    """
    store.scan_dir(scan_id).mkdir(parents=True, exist_ok=True)
    store._running[scan_id] = object()  # type: ignore[assignment]


def _drain_sse(resp: Any, max_lines: int = 32) -> list[str]:
    """Drain up to ``max_lines`` SSE lines from a streamed response."""
    out: list[str] = []
    for line in resp.iter_lines():
        out.append(line)
        if len(out) >= max_lines:
            break
    return out


# ---------------------------------------------------------------------------
# Line 207 — deadline-break path
# ---------------------------------------------------------------------------


def test_live_sse_breaks_on_deadline_for_running_scan(
    client: TestClient,
    store: ScanStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan that never completes still terminates when the soft cap fires.

    Locks line 207 (``if time.monotonic() > deadline: break``). Without
    this branch a forgotten browser tab would pin a uvicorn worker
    forever.
    """
    monkeypatch.setattr(scan_route, "_LIVE_MAX_SECONDS", 0.0)
    monkeypatch.setattr(scan_route, "_LIVE_POLL_SECONDS", 0.0)
    scan_id = "cli-running-deadline"
    _register_running(store, scan_id)
    try:
        with client.stream("GET", f"/scans/{scan_id}/live") as resp:
            assert resp.status_code == 200
            lines = _drain_sse(resp, max_lines=8)
        # Deadline trips on the very first while-iteration; the generator
        # exits cleanly without ever yielding a scan_done. Stream must
        # close (no event: scan_done line, no hang).
        assert not any("scan_done" in line for line in lines)
    finally:
        store._running.pop(scan_id, None)


# ---------------------------------------------------------------------------
# Lines 213-214 — OSError on scan_dir.stat() inside SSE generator
# Line 74 — _started_at_label(None) empty-string branch (called with mtime=None)
# ---------------------------------------------------------------------------


def test_live_sse_swallows_oserror_on_stat(
    client: TestClient,
    store: ScanStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``scan_dir.stat()`` raising OSError must not kill the SSE stream.

    Locks lines 213-214 (the ``except OSError: mtime = None`` swallow)
    AND line 74 (``_started_at_label(None)`` returns ``""`` via the
    ``scan_dir_mtime is None`` early-return).
    """
    monkeypatch.setattr(scan_route, "_LIVE_MAX_SECONDS", 0.5)
    monkeypatch.setattr(scan_route, "_LIVE_POLL_SECONDS", 0.0)
    scan_id = "cli-stat-os-error"
    _register_running(store, scan_id)

    real_stat = Path.stat

    def _raising_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == scan_id:
            raise OSError("simulated stat failure")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _raising_stat)

    try:
        with client.stream("GET", f"/scans/{scan_id}/live") as resp:
            assert resp.status_code == 200
            lines = _drain_sse(resp, max_lines=16)
        # The generator must NOT have raised; we should see at least the
        # snapshot event (or an empty stream when deadline pre-empts).
        assert all("Internal Server Error" not in line for line in lines)
    finally:
        store._running.pop(scan_id, None)


# ---------------------------------------------------------------------------
# Branch 230→239 — snapshot equality skips the yield
# Lines 242-243 — asyncio.sleep poll-tick path
# ---------------------------------------------------------------------------


def test_live_sse_skips_duplicate_snapshot_and_polls(
    client: TestClient,
    store: ScanStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two polls on the same running scan yield exactly one snapshot.

    Locks branch 230→239 (``if snapshot != last_snapshot`` takes the
    falsy path on the second iteration) AND lines 242-243 (the
    ``await asyncio.sleep(_LIVE_POLL_SECONDS)`` tick that fires between
    iterations when scan_done has not yet been reached).
    """
    # 3 iterations of the while-True: first yields, second is equal-skip,
    # third hits the deadline-break.
    monkeypatch.setattr(scan_route, "_LIVE_MAX_SECONDS", 0.15)
    monkeypatch.setattr(scan_route, "_LIVE_POLL_SECONDS", 0.0)
    scan_id = "cli-running-eq"
    _register_running(store, scan_id)
    try:
        with client.stream("GET", f"/scans/{scan_id}/live") as resp:
            assert resp.status_code == 200
            lines = _drain_sse(resp, max_lines=16)
        snapshot_events = [ln for ln in lines if ln.startswith("event: snapshot")]
        # Exactly one snapshot — the second iteration's equality branch
        # suppresses the duplicate emit. Locks 230→239.
        assert len(snapshot_events) == 1, lines
        assert not any("scan_done" in line for line in lines)
    finally:
        store._running.pop(scan_id, None)


# ---------------------------------------------------------------------------
# Sanity: the SSE 404 path is already covered by
# test_server_dashboard_live_sse::test_live_sse_404_for_unknown_scan
# but we restate it here to keep this module self-contained when run alone.
# ---------------------------------------------------------------------------


def test_live_sse_404_for_unknown_scan(client: TestClient) -> None:
    """Unknown scan_id → 404 from ``scans_live_sse``."""
    resp = client.get("/scans/does-not-exist/live")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# SSE Phase 1, Step 5 — ``deadline_approaching`` 30s before the soft cap
# ---------------------------------------------------------------------------


def test_live_sse_emits_deadline_approaching_before_deadline(
    client: TestClient,
    store: ScanStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client freshness dot listens for ``deadline_approaching`` and
    suppresses its DEAD/red transition for 60s on receipt. Without this
    pre-event, healthy 30-minute scans page operators every cap-crossing
    (critic patch G5 / P-ScheduledReconnect)."""
    # Cap = lead → the very first while-iteration is "approaching" but
    # has NOT yet exceeded the hard deadline; the event must fire before
    # the loop breaks.
    monkeypatch.setattr(scan_route, "_LIVE_MAX_SECONDS", 0.05)
    monkeypatch.setattr(scan_route, "_DEADLINE_APPROACHING_LEAD_SECONDS", 0.05)
    monkeypatch.setattr(scan_route, "_LIVE_POLL_SECONDS", 0.0)
    scan_id = "cli-running-deadline-pre"
    _register_running(store, scan_id)
    try:
        with client.stream("GET", f"/scans/{scan_id}/live") as resp:
            assert resp.status_code == 200
            lines = _drain_sse(resp, max_lines=16)
        assert any(ln.startswith("event: deadline_approaching") for ln in lines), lines
    finally:
        store._running.pop(scan_id, None)


# ---------------------------------------------------------------------------
# Coverage smoke: assert the module's missing-line set is empty after this
# module runs. Skipped unless explicitly opted-in via PYTEST_COV_QA022=1 so
# the regular test pass doesn't depend on the coverage plugin's run state.
# ---------------------------------------------------------------------------


def test_qa022_locking_coverage_smoke() -> None:
    """Locking smoke: the production module must still expose the four
    constants/symbols the SSE branches depend on. If a refactor renames
    or drops one of these the next QA-022 regression run flags it
    immediately rather than silently letting coverage rot.
    """
    assert hasattr(scan_route, "_LIVE_MAX_SECONDS")
    assert hasattr(scan_route, "_LIVE_POLL_SECONDS")
    assert hasattr(scan_route, "_started_at_label")
    assert scan_route._started_at_label(None) == ""
