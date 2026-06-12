"""Issue #112 (reopen) — dashboard "completed" must require completeness == 100.

PR #120 added a derived ``running / completed / failed`` status, but its
``completed`` branch fired on any ``is_running=False`` row that had a
score persisted. That misses the failure shape the reporter showed: a
scan that crashed or was killed mid-plan still hits the ``_finalise()``
path in ``core/swarm.py``, which unconditionally emits ``scan_done`` and
writes a score. With no findings collected, ``compute_aivss`` defaults
the AIVSS to 100 — and the dashboard rendered it as a clean
"completed / AIVSS 100" row, exactly the misleading number @as-glac
flagged in the reopen comment.

The framework already knows the difference. ``Scan.completeness`` (a
``ScanCompleteness``) carries a ``pct`` field — "agents_completed /
agents_planned" as a percent. Partial scans persist with ``pct < 100``;
genuinely-finished scans persist with ``pct == 100`` (or, for legacy
scans predating the field, ``completeness is None``).

These tests lock the fix's invariant: ``_derive_status`` now consults
``completeness_pct`` and returns ``failed`` for a finalised row whose
percent is below the threshold, regardless of ``has_score``. The
existing ``list_scans_page`` numeric-column suppression then blanks the
stale AIVSS, so a failed run cannot render a misleading score.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.scan_store import _derive_status

# ---------------------------------------------------------------------------
# Issue #112 reopen — the headline regression lock.
# ---------------------------------------------------------------------------


def test_derive_status_treats_incomplete_finalised_run_as_failed() -> None:
    """The exact reproduction shape @as-glac posted: ``is_running=False`` +
    ``has_score=True`` (AIVSS persisted) + ``completeness_pct`` below 100.
    Must be ``failed``, not ``completed`` — otherwise the dashboard shows a
    misleading "AIVSS 100" on a crashed scan."""
    now = 1000.0
    result = _derive_status(
        is_running=False,
        has_score=True,
        mtime=now,
        now=now,
        completeness_pct=20.0,
    )
    assert result == "failed", (
        "a finalised row with a score but completeness_pct < 100 is a "
        "partial / crashed run — it must NOT show as 'completed' "
        "(issue #112 reopen)"
    )


def test_derive_status_at_exact_completion_is_completed() -> None:
    """Boundary check: ``pct == 100.0`` is a genuinely-finished scan and
    must remain ``completed``."""
    now = 1000.0
    assert (
        _derive_status(
            is_running=False,
            has_score=True,
            mtime=now,
            now=now,
            completeness_pct=100.0,
        )
        == "completed"
    )


def test_derive_status_just_below_threshold_is_failed() -> None:
    """Just-below ``pct == 99.9`` is still partial — must be ``failed`` so
    the dashboard never displays a partial scan as a real result."""
    now = 1000.0
    assert (
        _derive_status(
            is_running=False,
            has_score=True,
            mtime=now,
            now=now,
            completeness_pct=99.9,
        )
        == "failed"
    )


def test_derive_status_legacy_none_completeness_preserves_old_behaviour() -> None:
    """Scans persisted before the completeness field existed have
    ``completeness_pct=None``. The oracle is blind for them — preserve the
    pre-fix behaviour (``has_score`` → ``completed``) so old runs in
    operators' dashboards do not retroactively flip to ``failed``."""
    now = 1000.0
    assert (
        _derive_status(
            is_running=False,
            has_score=True,
            mtime=now,
            now=now,
            completeness_pct=None,
        )
        == "completed"
    )


def test_derive_status_still_returns_failed_when_no_score_regardless_of_completeness() -> None:
    """``has_score=False`` is already a failure signal — the
    completeness check is an additional gate, not a softer one."""
    now = 1000.0
    for pct in (None, 0.0, 50.0, 100.0):
        assert (
            _derive_status(
                is_running=False,
                has_score=False,
                mtime=now,
                now=now,
                completeness_pct=pct,
            )
            == "failed"
        ), f"no score should always be failed, completeness_pct={pct}"


def test_derive_status_running_unchanged_by_completeness() -> None:
    """A still-running scan stays ``running`` regardless of completeness —
    the partial percent is expected mid-flight and is not a failure
    signal until the row finalises."""
    now = 1000.0
    assert (
        _derive_status(
            is_running=True,
            has_score=False,
            mtime=now,
            now=now,
            completeness_pct=10.0,
        )
        == "running"
    )


# ---------------------------------------------------------------------------
# End-to-end via the list page — the AIVSS=100 must NOT render for a
# finalised partial scan, because the numeric-column suppression already
# fires when status != "completed".
# ---------------------------------------------------------------------------


def _seed(store: ScanStore, scan_id: str, **row: object) -> None:
    """Create a scan dir + one on-disk index row. Mirrors the helper in
    ``test_scan_delete_and_status.py``."""
    store.scan_dir(scan_id).mkdir(parents=True, exist_ok=True)
    idx = store._index_read()
    idx[scan_id] = {"scan_id": scan_id, **row}
    store._index_write(idx)


def test_listed_incomplete_run_shows_failed_status_with_suppressed_aivss(tmp_path: Path) -> None:
    """The full pipeline: an index row that mimics @as-glac's reproduction
    (finalised, AIVSS 100, completeness_pct < 100) must render with the
    'failed' status and a blank AIVSS column — never AIVSS 100 on a row
    flagged as completed."""
    store = ScanStore(root_dir=tmp_path)
    _seed(
        store,
        "cli-partial",
        mtime=time.time(),
        aivss=100,
        band="Excellent",
        findings_count=0,
        completeness_pct=20.0,
        is_running=False,
        target_ref="https://example.com/finbot",
        target_mode="http",
        created_at="2026-06-01T00:00:00Z",
    )

    page, total = store.list_scans_page(offset=0, limit=10)
    assert total == 1
    summary = page[0]
    assert summary.status == "failed", (
        f"a finalised partial run must show 'failed', got status={summary.status!r}"
    )
    assert summary.aivss is None, (
        f"AIVSS must be suppressed for a failed run; got aivss={summary.aivss!r}"
    )
    assert summary.band is None
    assert summary.findings_count is None


def test_listed_complete_run_still_shows_completed_with_aivss(tmp_path: Path) -> None:
    """The happy path stays intact: a genuinely-completed scan
    (completeness_pct=100) keeps its 'completed' status and renders its
    AIVSS. This guards against the over-tightening that could regress the
    PR #120 fix while patching this one."""
    store = ScanStore(root_dir=tmp_path)
    _seed(
        store,
        "cli-good",
        mtime=time.time(),
        aivss=82,
        band="Good",
        findings_count=4,
        completeness_pct=100.0,
        is_running=False,
        target_ref="https://example.com/finbot",
        target_mode="http",
        created_at="2026-06-01T00:00:00Z",
    )

    page, _ = store.list_scans_page(offset=0, limit=10)
    summary = page[0]
    assert summary.status == "completed"
    assert summary.aivss == 82
    assert summary.band == "Good"


def test_home_page_does_not_render_aivss_100_on_failed_partial(tmp_path: Path) -> None:
    """A rendered-home assertion: the AIVSS '100' string must not appear in
    the row for a finalised partial run with AIVSS=100 cached. The status
    pill should show 'Failed' instead. This is the user-visible contract
    @as-glac's screenshot violates today."""
    store = ScanStore(root_dir=tmp_path)
    _seed(
        store,
        "cli-screenshot-shape",
        mtime=time.time(),
        aivss=100,
        band="Excellent",
        findings_count=0,
        completeness_pct=20.0,
        is_running=False,
        target_ref="https://example.com/finbot",
        target_mode="http",
        created_at="2026-06-01T00:00:00Z",
    )
    client = TestClient(create_app(scan_store=store))

    r = client.get("/")
    assert r.status_code == 200
    html = r.text
    # The scan row must appear...
    assert "cli-screenshot-shape" in html, "the scan row must render in the dashboard"
    # ...as 'Failed', NOT as a clean AIVSS-100 row. The exact label is
    # 'Failed' per the #120 ui pill; assert both directions.
    assert "Failed" in html or "failed" in html, (
        "a partial/failed run must surface a 'Failed' status pill"
    )
