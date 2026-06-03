"""QA-049 / QA-055 — Shared slide-over: probe endpoint sanity.

The Probes-tab row-click contract (existing
``/scan/<id>/probe?index=N``) is served by the polymorphic shared
``_slideover.html`` template; this test file complements
``test_executive_probes_table_and_slideover.py`` by adding the
contract checks for that shared-template surface: when an
operator clicks a probe row the drawer body emits the same locked
section labels as the finding endpoint (``Probe metadata``, ``Run
context``, ``Exact prompt sent``, ``Target response``, ``Judge
verdict``, ``Judge reasoning``, ``Evidence chain``, ``Reproduce``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
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


def _make_scan() -> Scan:
    return Scan(
        id="cli-slideover-probe-001",
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
        findings=[],
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


def _seed_memory_jsonl(scan_dir: Path) -> dict[str, object]:
    turn = {
        "agent": "goal-hijack-agent",
        "asi_category": "ASI01",
        "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
        "turn": 1,
        "strategy": "direct_injection",
        "prompt": "verbatim attacker prompt",
        "target_response": "target response text",
        "verdict": "fail",
        "confidence": 0.85,
        "reasoning": "judge reasoning sample",
        "seed_id": "PROBE-001",
        "attacker_refused": False,
    }
    record = {
        "timestamp": "2026-05-27T12:30:00+00:00",
        "record_type": "reflection",
        "payload": {
            "agent": turn["agent"],
            "content": json.dumps(turn),
        },
    }
    (scan_dir / "memory.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    return turn


def test_probe_slideover_endpoint_returns_locked_section_labels(
    client: TestClient, store: ScanStore
) -> None:
    """The existing ``/scan/<id>/probe`` endpoint shares the same
    seven QA-049 section labels with the new finding endpoint —
    polymorphic-loader contract.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/probe?index=0")
    assert resp.status_code == 200
    body = resp.text
    for label in (
        "Probe metadata",
        "Run context",
        "Exact prompt sent",
        "Target response",
        "Judge verdict",
        "Judge reasoning",
        "Evidence chain",
    ):
        assert label in body, f"probe slide-over missing section {label!r}"
    # Reproduce was removed from the detail view (operator request).
    assert "Reproduce" not in body


def test_probe_row_carries_drawer_href_for_polymorphic_loader(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    # Probe row's ``data-probe-href`` is the polymorphic-loader entry
    # point for the Probes tab (paired with ``data-finding-href`` on
    # the Findings tab). Per-agent grouping (2026-06-03) keys it on the
    # agent so the modal renders that agent's whole conversation.
    assert f'data-probe-href="/scan/{scan.id}/probe?group=goal-hijack-agent"' in body


def test_probe_drawer_html_omits_reproduce_block(client: TestClient, store: ScanStore) -> None:
    """Reproduce CLI block was removed from the detail view (operator request)."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/probe?index=0")
    body = resp.text
    assert "Reproduce" not in body
    assert "agent-guardian probe" not in body
