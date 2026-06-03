"""QA-049 / QA-055 — Shared slide-over: finding endpoint.

Server-rendered ``GET /scan/<scan_id>/finding/<finding_id>`` returns
the polymorphic ``_slideover.html`` body fragment. Same template,
same section labels, same reproduce-CLI snippet as the probe endpoint
— only the ``kind`` and the underlying record differ.
"""

from __future__ import annotations

import json
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


def _make_finding(
    fid: str = "f-crit-1",
    *,
    probe_id: str = "PROBE-001",
    severity: Severity = Severity.CRITICAL,
    asi: AsiCategory = AsiCategory.ASI01,
) -> Finding:
    return Finding(
        id=fid,
        probe_id=probe_id,
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=2,
        success=True,
        confidence=0.91,
        summary=f"finding {fid}: prompt injection observed",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
    )


def _make_scan(*, findings: list[Finding] | None = None) -> Scan:
    return Scan(
        id="cli-slideover-finding-001",
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
        findings=findings if findings is not None else [_make_finding()],
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


def _seed_memory_jsonl(
    scan_dir: Path,
    *,
    probe_id: str = "PROBE-001",
    asi_value: str = "ASI01",
    count: int = 1,
) -> list[dict[str, object]]:
    """Write ``count`` correlated probe attempts under ``probe_id``."""
    turns: list[dict[str, object]] = []
    lines: list[str] = []
    for i in range(count):
        turn: dict[str, object] = {
            "agent": "goal-hijack-agent",
            "asi_category": asi_value,
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": i + 1,
            "strategy": "direct_injection",
            "prompt": f"verbatim attack prompt {i}",
            "target_response": f"target response text {i}",
            "verdict": "fail" if i == 0 else "pass",
            "confidence": 0.85,
            "reasoning": f"judge reasoning sample {i}",
            "seed_id": probe_id,
            "attacker_refused": False,
        }
        record = {
            "timestamp": f"2026-05-27T12:{30 + i:02d}:00+00:00",
            "record_type": "reflection",
            "payload": {
                "agent": turn["agent"],
                "content": json.dumps(turn),
            },
        }
        turns.append(turn)
        lines.append(json.dumps(record))
    (scan_dir / "memory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return turns


# ---------------------------------------------------------------------------
# 1. Endpoint renders the shared template with the expected sections
# ---------------------------------------------------------------------------


def test_finding_slideover_returns_200(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    assert resp.status_code == 200


def test_finding_slideover_renders_locked_sections(client: TestClient, store: ScanStore) -> None:
    """Same QA-049 section labels as the probe endpoint — the shared
    ``_slideover.html`` template is the single source of truth.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    for label in (
        "Finding metadata",
        "Exact prompt sent",
        "Target response",
        "Judge verdict",
        "Judge reasoning",
        "Evidence chain",
        "Reproduce",
    ):
        assert label in body, f"finding slide-over missing section {label!r}"


def test_finding_slideover_uses_shared_sheet_class(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert 'data-slideover-kind="finding"' in body
    assert 'class="exec-slideover-sheet"' in body


def test_finding_slideover_surfaces_correlated_prompt_and_response(
    client: TestClient, store: ScanStore
) -> None:
    """When a Finding's probe_id matches a memory.jsonl record, the
    verbatim prompt + target_response + reasoning surface inline.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    turns = _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert turns[0]["prompt"] in body
    assert turns[0]["target_response"] in body
    assert turns[0]["reasoning"] in body


def test_finding_slideover_reproduce_cli_includes_scan_and_probe(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert f"--scan {scan.id}" in body
    assert "--probe PROBE-001" in body


def test_finding_slideover_header_template_emitted(client: TestClient, store: ScanStore) -> None:
    """Header chip slot is a ``<template data-slideover-header>`` that
    the JS hoists into the slide-over chrome.
    """
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert "data-slideover-header" in body
    assert 'data-kind="finding"' in body
    assert 'data-record-id="f-crit-1"' in body


# ---------------------------------------------------------------------------
# 2. Per-turn thread surfaces multi-turn evidence (composes with QA-054)
# ---------------------------------------------------------------------------


def test_finding_slideover_renders_per_turn_thread_when_multi_turn(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=3)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert "Per-turn conversation thread" in body
    assert 'class="exec-slideover-thread"' in body
    # Three numbered subsections, one per correlated probe attempt.
    assert body.count('class="exec-slideover-thread__item"') == 3


def test_finding_slideover_omits_thread_when_single_turn(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=1)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert "Per-turn conversation thread" not in body


# ---------------------------------------------------------------------------
# 3. Findings tab row exposes the new ``data-finding-href`` for fetch
# ---------------------------------------------------------------------------


def test_findings_tab_row_carries_finding_href(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    _persist(store, scan)
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    body = resp.text
    # The shared slide-over loader keys off ``data-finding-href``.
    marker = f'data-finding-href="/scan/{scan.id}/finding/f-crit-1"'
    assert marker in body, "findings row missing data-finding-href attribute"


def test_findings_slideover_js_handles_finding_fetch(client: TestClient) -> None:
    resp = client.get("/static/executive_findings.js")
    assert resp.status_code == 200
    body = resp.text
    # New polymorphic loader is wired.
    assert "loadFindingSheet" in body
    assert "isSafeFindingHref" in body
    assert "data-finding-href" in body
