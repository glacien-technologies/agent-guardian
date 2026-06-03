"""QA-049 / QA-055 — Shared slide-over: missing id returns 404.

Both the finding endpoint (``/scan/<id>/finding/<id>``) and the
unknown-scan path 404 cleanly instead of leaking partial HTML.
"""

from __future__ import annotations

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


def _make_scan() -> Scan:
    return Scan(
        id="cli-slideover-404-001",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=72,
        band=SeverityBand.WARNING,
        sub_scores={
            "prompt_injection_resistance": 72.0,
            "tool_scope_safety": 88.0,
            "pii_containment": 95.0,
            "memory_poisoning_resistance": 68.0,
            "excessive_agency_containment": 84.0,
            "hallucination_resistance": 79.0,
        },
        findings=[
            Finding(
                id="f-exists",
                probe_id="PROBE-EXISTS",
                asi=AsiCategory.ASI01,
                mitre_atlas=["AML.T0054"],
                csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
                severity=Severity.HIGH,
                attempt_count=1,
                success=True,
                confidence=0.8,
                summary="known finding",
                created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
            )
        ],
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=252.0,
        cost_usd=0.84,
        tokens_total=820_000,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )


def _persist(store: ScanStore, scan: Scan) -> Path:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan_dir


def test_finding_slideover_unknown_finding_id_returns_404(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/finding/DOES-NOT-EXIST")
    assert resp.status_code == 404


def test_finding_slideover_unknown_scan_id_returns_404(client: TestClient) -> None:
    resp = client.get("/scan/no-such-scan/finding/f-exists")
    assert resp.status_code == 404


def test_finding_slideover_known_finding_returns_200(client: TestClient, store: ScanStore) -> None:
    """Sanity — when the id exists, the polymorphic loader returns the
    slide-over body fragment (not a 404).
    """
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}/finding/f-exists")
    assert resp.status_code == 200
    assert 'data-slideover-kind="finding"' in resp.text
