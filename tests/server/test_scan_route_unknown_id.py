"""QA-022 — unknown-id / page-param / report-decode branch coverage.

Locks the uncovered non-SSE branches in
``src/agent_guardian/server/routes/scan.py``:

* line 87 — ``/scan/<id>`` HTTPException(404) when there is no running
  registration AND no scan_dir on disk.
* lines 92-93 — ``except OSError: mtime = None`` inside ``scan_view``
  when ``scan_dir.stat()`` raises (e.g. EACCES on the directory).
* lines 99-100 — ``except ValueError: page = 1`` when ``?page=`` carries
  a non-integer value.
* lines 183-184 — ``except (OSError, json.JSONDecodeError)`` warning
  branch inside ``scans_report`` when ``scan.raw.json`` exists but the
  bytes won't decode.

The redirect handler (``scans_redirect`` at /scans/{id}) is already
covered by ``tests/unit/test_server_dashboard_rendering`` for the
happy-path 307 and the unknown-id 404; the test below adds the
query-string-preservation regression that QA-020 introduced (the
``qs = request.url.query`` branch) so the file is a self-contained
QA-022 closure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def _make_scan(scan_id: str = "cli-qa022-known") -> Scan:
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
                attempt_count=1,
                success=True,
                confidence=0.9,
                summary="seed",
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


# ---------------------------------------------------------------------------
# Line 87 — /scan/<id> 404 for an id that is neither running nor on disk
# ---------------------------------------------------------------------------


def test_scan_view_404_for_truly_unknown_id(client: TestClient) -> None:
    """``/scan/<id>`` raises HTTP 404 when nothing exists for the id.

    The redirect handler at ``/scans/<id>`` also short-circuits to 404
    in the same scenario, but ``/scan/<id>`` is the legacy bookmark URL
    and gets its own branch (line 87). Locks that branch.
    """
    resp = client.get("/scan/no-such-scan", follow_redirects=False)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Lines 92-93 — OSError on scan_dir.stat() inside scan_view
# ---------------------------------------------------------------------------


def test_scan_view_swallows_oserror_on_stat(
    client: TestClient,
    store: ScanStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``scan_dir.stat()`` raising OSError must NOT 500 the dashboard.

    The route swallows OSError into ``mtime = None`` so an EACCES on the
    scan directory still renders the editorial dashboard with an empty
    "Started" label. Locks lines 92-93.

    The view's try-block reads ``scan_dir.stat().st_mtime if scan_dir.is_dir()
    else None``. ``is_dir()`` internally calls ``stat()`` too, and the
    earlier ``store.is_running()`` / ``store.scan_dir(...).is_dir()`` short
    circuits also walk ``stat()``. To target ONLY the inline ``stat()``
    call inside the try-block we let the first ``stat`` calls succeed
    (so ``is_dir()`` returns True and the 404 short-circuit does not
    fire) and then fail the next ``stat`` — which is the one whose
    OSError the try/except is designed to swallow.
    """
    scan = _make_scan("cli-qa022-stat-oserror")
    _persist(store, scan)

    real_stat = Path.stat
    # Allow enough successful stat() calls for is_running()'s is_dir(),
    # the 404 short-circuit's is_dir(), and the try-block's is_dir();
    # then raise on the NEXT stat() — that is the bare ``scan_dir.stat()``
    # whose OSError the try/except on lines 92-93 swallows.
    call_count = {"n": 0}
    # Stat-call ledger on the scan_dir during scan_view():
    #   1) ``store.is_running()`` → ``scan_dir.is_dir()`` (stat #1)
    #   2) ``scan_dir.is_dir()`` inside the try-block (stat #2)
    #   3) ``scan_dir.stat()`` — the one we want to fail; OSError swallowed.
    # ``load_completed()`` reads scan.json directly so it doesn't stat the
    # scan-dir, and the 404 short-circuit's ``store.scan_dir(...).is_dir()``
    # is gated by ``scan is None`` — which is False here because we persisted
    # a real scan. So 2 successful stats then raise on the 3rd.
    allow_before_raise = 2

    def _raising_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == scan.id:
            call_count["n"] += 1
            if call_count["n"] > allow_before_raise:
                raise OSError("simulated stat failure")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", _raising_stat)
    resp = client.get(f"/scan/{scan.id}", follow_redirects=False)
    # Renders despite the stat failure; the page is still 200.
    assert resp.status_code == 200
    # Confirm we actually exercised the OSError path (not just early-returned).
    assert call_count["n"] > allow_before_raise


# ---------------------------------------------------------------------------
# Lines 99-100 — ValueError on non-integer ?page= falls back to 1
# ---------------------------------------------------------------------------


def test_scan_view_non_integer_page_param_falls_back_to_one(
    client: TestClient, store: ScanStore
) -> None:
    """``?page=banana`` must not 500 — the route clamps to 1.

    Locks lines 99-100 (``except ValueError: page = 1``).
    """
    scan = _make_scan("cli-qa022-bad-page")
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?page=banana", follow_redirects=False)
    assert resp.status_code == 200


def test_scan_view_negative_page_clamps_to_one(client: TestClient, store: ScanStore) -> None:
    """``?page=-5`` clamps to 1 via the ``max(1, int(...))`` guard.

    The branch is the OTHER side of the ValueError path — covers the
    integer-parse-OK path with a value that needs clamping.
    """
    scan = _make_scan("cli-qa022-neg-page")
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?page=-5", follow_redirects=False)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Lines 183-184 — scans_report warning branch when scan.raw.json is garbage
# ---------------------------------------------------------------------------


def test_scans_report_warns_and_404s_when_raw_json_unparseable(
    client: TestClient, store: ScanStore, caplog: pytest.LogCaptureFixture
) -> None:
    """``scans_report`` logs a warning and 404s when ``scan.raw.json``
    exists but can't be JSON-decoded AND there's no usable ``scan.json``.

    Locks lines 183-184 (the ``except (OSError, JSONDecodeError)``
    warning branch). ``load_completed`` returns None because the raw
    file is garbage; the route then re-opens the same file in its
    fallback loop, hits JSONDecodeError, logs, and falls through to the
    final ``HTTPException(404, "no report for scan: ...")``.
    """
    scan_id = "cli-qa022-garbage-raw"
    scan_dir = store.scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    # Garbage that is NOT valid JSON. load_completed swallows and returns
    # None; scans_report retries and hits the except branch.
    (scan_dir / "scan.raw.json").write_text("{not valid json", encoding="utf-8")
    with caplog.at_level("WARNING", logger="agent_guardian.server.routes.scan"):
        resp = client.get(f"/scans/{scan_id}/report")
    assert resp.status_code == 404
    assert "no report for scan" in resp.json().get("detail", "")
    assert any("scans_report: cannot read" in rec.getMessage() for rec in caplog.records), [
        r.getMessage() for r in caplog.records
    ]


# ---------------------------------------------------------------------------
# Bonus: lock the redirect-with-query-string behaviour (covered already
# but kept here so the QA-022 module is a single-source closure).
# ---------------------------------------------------------------------------


def test_scans_redirect_preserves_query_string(client: TestClient, store: ScanStore) -> None:
    """``/scans/<id>?page=2&theme=narrative`` → 307 ``/scan/<id>?page=2&theme=narrative``."""
    scan = _make_scan("cli-qa022-redir-qs")
    _persist(store, scan)
    resp = client.get(f"/scans/{scan.id}?page=2&theme=narrative", follow_redirects=False)
    assert resp.status_code == 307
    loc = resp.headers["location"]
    assert loc.startswith(f"/scan/{scan.id}?")
    assert "page=2" in loc
    assert "theme=narrative" in loc
