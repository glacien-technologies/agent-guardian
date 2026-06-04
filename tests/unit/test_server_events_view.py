"""Tests for GET /scan/{id}/events/view — the rendered-JSONL evidence page.

The slideover's "View JSONL events for this probe" link used to open the
``text/event-stream`` endpoint, which dumps the raw replay in a browser tab.
This route instead renders the on-disk JSONL (``events.jsonl`` +
``recon_probes.jsonl``) as pretty-printed, syntax-highlighted JSON, optionally
filtered to a single probe id.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.routes.events import _collect_jsonl_records


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    return TestClient(create_app(scan_store=store))


def _seed_scan(store: ScanStore, scan_id: str) -> Path:
    scan_dir = store.scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "events.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"seq": 1, "kind": "phase_start", "payload": {"phase": "recon"}}),
                json.dumps({"seq": 2, "kind": "probe", "payload": {"probe_id": "P-abc", "n": 3}}),
                json.dumps({"seq": 3, "kind": "probe", "payload": {"probe_id": "P-xyz"}}),
                "   ",  # blank line — must be skipped
                "{not valid json",  # corrupt — must be skipped, not raise
            ]
        ),
        encoding="utf-8",
    )
    (scan_dir / "recon_probes.jsonl").write_text(
        json.dumps({"probe_id": "P-abc", "band": "tools", "intent": "seed", "prompt": "hi"}) + "\n",
        encoding="utf-8",
    )
    return scan_dir


def test_events_view_renders_pretty_json(client: TestClient, store: ScanStore) -> None:
    _seed_scan(store, "scan-1")
    resp = client.get("/scan/scan-1/events/view")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    # Pretty-printed (indented) JSON, the highlighter, and the styled shell.
    assert '<pre class="json">' in body
    assert "phase_start" in body
    assert "function highlight" in body  # the client-side colorizer is present
    assert "JSONL events" in body


def test_events_view_filters_by_probe(client: TestClient, store: ScanStore) -> None:
    _seed_scan(store, "scan-2")
    resp = client.get("/scan/scan-2/events/view", params={"probe": "P-abc"})
    assert resp.status_code == 200
    body = resp.text
    assert "P-abc" in body
    # The unrelated probe record must be filtered out.
    assert "P-xyz" not in body
    # Both the event row and the recon-probe-log row for P-abc are included.
    assert "recon_probes.jsonl" in body


def test_events_view_unknown_scan_404(client: TestClient) -> None:
    resp = client.get("/scan/does-not-exist/events/view")
    assert resp.status_code == 404


def test_collect_jsonl_records_is_defensive_and_capped(tmp_path: Path) -> None:
    # Missing files -> no rows, no raise.
    assert _collect_jsonl_records(tmp_path / "nope", None) == []

    scan_dir = tmp_path / "s"
    scan_dir.mkdir()
    lines = [json.dumps({"seq": i, "kind": "probe", "payload": {"i": i}}) for i in range(600)]
    (scan_dir / "events.jsonl").write_text("\n".join(lines), encoding="utf-8")
    records = _collect_jsonl_records(scan_dir, None)
    assert len(records) == 500  # capped at _MAX_VIEW_RECORDS
    # Each record carries a pretty-printed (indented) JSON body.
    assert records[0]["pretty"].startswith("{\n")
    assert records[0]["kind"] == "probe"
