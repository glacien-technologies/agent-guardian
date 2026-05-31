"""Executive Dashboard — topbar logo asset rendering.

Covers the dashboard-logo slice of the Executive UX fix bundle:

* ``/static/logo.svg`` is served by the static mount with the right
  content-type and SVG body.
* The Executive topbar HTML embeds ``/static/logo.svg`` (not the legacy
  ``AG`` text mark).
* The ``.exec-topbar-logo`` CSS rule with a ``32px`` height is present in
  the shipped ``executive.css``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.server import ScanStore, create_app


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


def _persist_scan(store: ScanStore, scan_id: str = "cli-logo-001") -> Scan:
    scan = Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=84,
        band=SeverityBand.GOOD,
        sub_scores={},
        findings=[],
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=10.0,
        cost_usd=0.05,
        tokens_total=1000,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=timezone.utc),
    )
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan


def test_logo_svg_served_via_static_mount(client: TestClient) -> None:
    """The /static/logo.svg asset must be reachable through the static mount."""
    resp = client.get("/static/logo.svg")
    assert resp.status_code == 200
    assert "image/svg" in resp.headers["content-type"]
    body = resp.text
    assert "<svg" in body
    # The logo must be self-contained — no external font references.
    assert "fonts.googleapis.com" not in body
    assert "@import" not in body


def test_executive_topbar_embeds_logo_svg(client: TestClient, store: ScanStore) -> None:
    """The Executive topbar HTML must reference /static/logo.svg."""
    scan = _persist_scan(store)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    assert resp.status_code == 200
    body = resp.text
    # New logo asset wired in.
    assert "/static/logo.svg" in body
    assert 'class="exec-topbar-logo"' in body
    # The hardcoded "AG" text mark must be gone.
    assert '<span class="exec-topbar__mark" aria-hidden="true">AG</span>' not in body


def test_executive_css_defines_topbar_logo_rule(client: TestClient) -> None:
    """executive.css must ship a `.exec-topbar-logo` rule sizing the logo at 32px."""
    resp = client.get("/static/executive.css")
    assert resp.status_code == 200
    css = resp.text
    assert ".exec-topbar-logo" in css
    # The height token from the design lock — load-bearing for vertical rhythm.
    assert "32px" in css
