"""QA-054 — server-side multi-turn finding aggregation tests.

Each Finding row already represents one rolled-up attack thread (one
probe_id / agent). Its per-turn detail is the matched evidence list
attached by :func:`_attach_evidence_to_findings`. QA-054 surfaces that
detail as inline child rows so the operator sees ``N of M turns
failed`` on the parent and a chevron toggle expands the per-turn
prompt / response / verdict triples.

These tests assert the contract:

* A multi-turn finding (>=2 correlated evidence rows) gets a chevron
  toggle, a ``data-parent`` parent row, and N hidden child ``<tr>``
  rows below it.
* A single-turn finding renders flat — no chevron, no children — for
  back-compat with the QA-031 / QA-051 / QA-053 markup contracts.
* The parent's ``aria-label`` and a visible progress chip carry the
  ``N of M turns failed`` summary computed server-side.
* Child rows are marked ``hidden`` on initial render (collapsed by
  default; the chevron click handler in ``executive_findings.js``
  reveals them).
* Filter chips operate on parent rows only; children inherit parent
  visibility via the JS pipeline (assertion on the chip toolbar
  markup since the JS itself is exercised in browser tests).
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
    fid: str,
    probe_id: str,
    severity: Severity = Severity.HIGH,
    asi: AsiCategory = AsiCategory.ASI01,
    attempt_count: int = 1,
) -> Finding:
    return Finding(
        id=fid,
        probe_id=probe_id,
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=attempt_count,
        success=True,
        confidence=0.92,
        summary=f"{fid}: prompt injection observed",
        created_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC),
    )


def _make_scan(findings: list[Finding]) -> Scan:
    return Scan(
        id="cli-multiturn-001",
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="tests/example.txt",
        tier=Tier.T2_HIGH,
        aivss=64,
        band=SeverityBand.WARNING,
        sub_scores={
            "prompt_injection_resistance": 64.0,
            "tool_scope_safety": 80.0,
            "pii_containment": 95.0,
            "memory_poisoning_resistance": 70.0,
            "excessive_agency_containment": 84.0,
            "hallucination_resistance": 79.0,
        },
        findings=findings,
        asi_scores={cat: 80.0 for cat in AsiCategory},
        duration_seconds=180.0,
        cost_usd=0.61,
        tokens_total=510_000,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        created_at=datetime(2026, 5, 27, 12, 5, 0, tzinfo=UTC),
    )


def _persist(store: ScanStore, scan: Scan) -> Path:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan_dir


def _write_reflections(
    scan_dir: Path,
    *,
    probe_id: str,
    agent: str,
    verdicts: list[str],
    asi_category: str = "ASI01",
) -> None:
    """Append reflection records for a single (probe_id, agent) thread.

    One record per verdict — turn numbers count up from 1. The records
    are encoded in the canonical ``memory.jsonl`` shape so the dashboard
    view-model picks them up via ``_assemble_probes_list``.
    """
    path = scan_dir / "memory.jsonl"
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    lines: list[str] = []
    for i, verdict in enumerate(verdicts):
        turn = {
            "agent": agent,
            "asi_category": asi_category,
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": i + 1,
            "strategy": "multi_turn_escalation",
            "prompt": f"attacker-prompt-{probe_id}-{i + 1}",
            "target_response": f"target-response-{probe_id}-{i + 1}",
            "verdict": verdict,
            "confidence": 0.81,
            "reasoning": f"reasoning-{probe_id}-{i + 1}",
            "seed_id": probe_id,
            "attacker_refused": False,
        }
        rec = {
            "timestamp": f"2026-05-27T12:{30 + i:02d}:00+00:00",
            "record_type": "reflection",
            "payload": {"agent": agent, "content": json.dumps(turn)},
        }
        lines.append(json.dumps(rec))
    path.write_text(existing + "\n".join(lines) + "\n", encoding="utf-8")


def _findings_pane(body: str) -> str:
    start = body.find('id="tabpanel-findings"')
    assert start != -1
    end = body.find('id="tabpanel-probes"', start)
    return body[start : end if end != -1 else len(body)]


# ----------------------------------------------------------------------
# Multi-turn aggregation: parent row with chevron + N child rows
# ----------------------------------------------------------------------


def test_multi_turn_finding_renders_chevron_toggle(client: TestClient, store: ScanStore) -> None:
    finding = _make_finding("f-multi", "PROBE-MT-1", attempt_count=3)
    scan = _make_scan([finding])
    scan_dir = _persist(store, scan)
    _write_reflections(
        scan_dir,
        probe_id="PROBE-MT-1",
        agent="goal-hijack-agent",
        verdicts=["pass", "inconclusive", "fail"],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # Parent row carries the multi-turn marker class + data attributes.
    assert "exec-findings-table__row--has-children" in pane
    assert 'data-parent="f-multi"' in pane
    assert 'data-turn-total="3"' in pane
    assert 'data-turn-failed="1"' in pane
    # Chevron toggle button is wired with the toggle action contract.
    assert 'data-action="toggle-turns"' in pane
    assert 'data-target="f-multi"' in pane
    assert 'aria-expanded="false"' in pane


def test_multi_turn_finding_emits_one_child_per_turn(client: TestClient, store: ScanStore) -> None:
    finding = _make_finding("f-mt2", "PROBE-MT-2", attempt_count=3)
    scan = _make_scan([finding])
    scan_dir = _persist(store, scan)
    _write_reflections(
        scan_dir,
        probe_id="PROBE-MT-2",
        agent="goal-hijack-agent",
        verdicts=["pass", "fail", "fail"],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # One child <tr> per turn — assert by the unique data-child-of marker.
    assert pane.count('data-child-of="f-mt2"') == 3
    # Children are hidden by default (collapsed); the chevron click
    # reveals them via the JS handler.
    assert "exec-findings-table__row--child is-collapsed" in pane


def test_multi_turn_progress_label_summarises_failures(
    client: TestClient, store: ScanStore
) -> None:
    finding = _make_finding("f-mt3", "PROBE-MT-3", attempt_count=4)
    scan = _make_scan([finding])
    scan_dir = _persist(store, scan)
    _write_reflections(
        scan_dir,
        probe_id="PROBE-MT-3",
        agent="tool-misuse-agent",
        verdicts=["pass", "fail", "pass", "fail"],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # "2 of 4 turns failed" appears both in the visible progress chip
    # and the aria-label so screen-reader users get the same headline.
    assert "2 of 4 turns failed" in pane


def test_multi_turn_child_rows_carry_prompt_and_response_previews(
    client: TestClient, store: ScanStore
) -> None:
    finding = _make_finding("f-mt4", "PROBE-MT-4", attempt_count=2)
    scan = _make_scan([finding])
    scan_dir = _persist(store, scan)
    _write_reflections(
        scan_dir,
        probe_id="PROBE-MT-4",
        agent="goal-hijack-agent",
        verdicts=["pass", "fail"],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # Prompt and response previews from the seeded reflection records
    # reach the rendered child rows verbatim (whitespace-collapsed).
    assert "attacker-prompt-PROBE-MT-4-1" in pane
    assert "target-response-PROBE-MT-4-2" in pane
    # Per-turn verdict labels honour the no-raw-enum rule.
    assert "EXPLOITED" in pane
    assert "DEFENDED" in pane


# ----------------------------------------------------------------------
# Single-turn back-compat: flat row, no chevron, no children
# ----------------------------------------------------------------------


def test_single_turn_finding_renders_flat(client: TestClient, store: ScanStore) -> None:
    finding = _make_finding("f-flat", "PROBE-ST-1", attempt_count=1)
    scan = _make_scan([finding])
    scan_dir = _persist(store, scan)
    _write_reflections(
        scan_dir,
        probe_id="PROBE-ST-1",
        agent="goal-hijack-agent",
        verdicts=["fail"],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # No chevron, no children, no parent marker class for a single-turn
    # finding — the existing QA-031 / QA-051 / QA-053 markup is preserved.
    assert 'data-parent="f-flat"' not in pane
    assert 'data-child-of="f-flat"' not in pane
    assert 'data-target="f-flat"' not in pane


def test_single_turn_finding_keeps_legacy_turn_column(client: TestClient, store: ScanStore) -> None:
    finding = _make_finding("f-flat-2", "PROBE-ST-2", attempt_count=1)
    scan = _make_scan([finding])
    scan_dir = _persist(store, scan)
    _write_reflections(
        scan_dir,
        probe_id="PROBE-ST-2",
        agent="goal-hijack-agent",
        verdicts=["fail"],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # The Turn column still shows the canonical (earliest) turn number
    # for the single-turn case — no ``N/M`` aggregation badge.
    assert "1/1" not in pane


# ----------------------------------------------------------------------
# Filter chip toolbar continues to operate on parent rows (QA-053)
# ----------------------------------------------------------------------


def test_filter_chip_toolbar_still_present_with_multi_turn_rows(
    client: TestClient, store: ScanStore
) -> None:
    finding = _make_finding("f-fc", "PROBE-FC-1", attempt_count=3)
    scan = _make_scan([finding])
    scan_dir = _persist(store, scan)
    _write_reflections(
        scan_dir,
        probe_id="PROBE-FC-1",
        agent="goal-hijack-agent",
        verdicts=["fail", "fail", "fail"],
    )
    resp = client.get(f"/scan/{scan.id}?theme=executive")
    pane = _findings_pane(resp.text)
    # QA-053 chip toolbar still mounts above the table.
    assert 'id="exec-findings-filter"' in pane
    assert 'data-filter-group="severity"' in pane
    # Counter denominator still equals the parent count, not parent+child.
    assert 'data-counter-total="1"' in pane


# ----------------------------------------------------------------------
# Unit-level: _attach_evidence_to_findings adds the QA-054 fields
# ----------------------------------------------------------------------


def test_attach_evidence_populates_turn_aggregation_fields() -> None:
    """Direct unit-level check of the view-model field contract.

    Skips the HTTP layer so the field shape is locked even when no Jinja
    template consumes it (e.g. a future SSE diff stream that wants the
    raw turn-children payload).
    """
    from agent_guardian.server.dashboard_view import _attach_evidence_to_findings

    findings_items: list[dict[str, object]] = [
        {
            "id": "f-unit",
            "probe_id": "PROBE-UNIT-1",
            "asi_code": "ASI01",
            "summary": "unit",
            "agent_name": "",
        }
    ]
    probes_list: list[dict[str, object]] = [
        {
            "agent": "goal-hijack-agent",
            "asi_category": "ASI01",
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": 1,
            "probe_id": "PROBE-UNIT-1",
            "prompt": "p1",
            "target_response": "r1",
            "verdict": "pass",
            "confidence": 0.7,
        },
        {
            "agent": "goal-hijack-agent",
            "asi_category": "ASI01",
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": 2,
            "probe_id": "PROBE-UNIT-1",
            "prompt": "p2",
            "target_response": "r2",
            "verdict": "fail",
            "confidence": 0.95,
        },
    ]
    _attach_evidence_to_findings(findings_items, probes_list)
    item = findings_items[0]
    assert item["is_multi_turn"] is True
    assert item["turn_total"] == 2
    assert item["turn_failed"] == 1
    assert item["turn_progress_label"] == "1 of 2 turns failed"
    children = item["turn_children"]
    assert isinstance(children, list) and len(children) == 2
    assert children[0]["verdict_label"] == "DEFENDED"
    assert children[1]["verdict_label"] == "EXPLOITED"
    assert children[1]["confidence_pct"] == "95%"


def test_attach_evidence_single_turn_is_not_multi_turn() -> None:
    """A single correlated evidence row keeps ``is_multi_turn`` False so the
    template short-circuits to the flat, back-compat row layout."""
    from agent_guardian.server.dashboard_view import _attach_evidence_to_findings

    findings_items: list[dict[str, object]] = [
        {
            "id": "f-single",
            "probe_id": "PROBE-UNIT-2",
            "asi_code": "ASI02",
            "summary": "single",
            "agent_name": "",
        }
    ]
    probes_list: list[dict[str, object]] = [
        {
            "agent": "tool-misuse-agent",
            "asi_category": "ASI02",
            "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
            "turn": 1,
            "probe_id": "PROBE-UNIT-2",
            "prompt": "only",
            "target_response": "only-resp",
            "verdict": "fail",
            "confidence": 0.6,
        }
    ]
    _attach_evidence_to_findings(findings_items, probes_list)
    item = findings_items[0]
    assert item["is_multi_turn"] is False
    assert item["turn_total"] == 1
    assert item["turn_failed"] == 1
    assert item["turn_progress_label"] == ""


def test_attach_evidence_empty_probes_sets_safe_defaults() -> None:
    """When no probes correlate, the QA-054 fields still exist with empty
    defaults so the Jinja template never trips KeyError."""
    from agent_guardian.server.dashboard_view import _attach_evidence_to_findings

    findings_items: list[dict[str, object]] = [
        {
            "id": "f-empty",
            "probe_id": "",
            "asi_code": "",
            "summary": "empty",
            "agent_name": "",
        }
    ]
    _attach_evidence_to_findings(findings_items, [])
    item = findings_items[0]
    assert item["turn_children"] == []
    assert item["turn_total"] == 0
    assert item["turn_failed"] == 0
    assert item["is_multi_turn"] is False
    assert item["turn_progress_label"] == ""
