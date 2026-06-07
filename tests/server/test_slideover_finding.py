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
    ):
        assert label in body, f"finding slide-over missing section {label!r}"
    # Reproduce is intentionally probe-only now (removed from findings).
    assert "Reproduce" not in body


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


def test_finding_slideover_omits_reproduce_and_linked_remediation(
    client: TestClient, store: ScanStore
) -> None:
    """Findings no longer carry the Reproduce CLI block or the empty
    'Linked remediation' placeholder — the finding view is for triage."""
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert "Reproduce" not in body
    assert "agent-guardian probe" not in body
    assert "Linked remediation" not in body


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


def test_finding_slideover_renders_chat_conversation_when_multi_turn(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=3)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    # QA-061 — multi-turn renders as a chat conversation, one turn block
    # per correlated probe attempt, each with an outgoing attacker bubble
    # and an incoming target bubble.
    assert "Attack conversation" in body
    assert 'class="exec-chat"' in body
    assert body.count('class="exec-chat__turn"') == 3
    assert body.count("exec-chat__bubble--out") == 3
    assert body.count("exec-chat__bubble--in") == 3


def test_finding_slideover_omits_chat_when_single_turn(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_memory_jsonl(scan_dir, count=1)
    resp = client.get(f"/scan/{scan.id}/finding/f-crit-1")
    body = resp.text
    assert "Attack conversation" not in body
    # Single-turn keeps the flat prompt/response layout.
    assert "Exact prompt sent" in body


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


# ---------------------------------------------------------------------------
# 4. Field-correctness: the representative turn anchors prompt / response /
#    verdict / reasoning to a SINGLE exchange (QA-061).
# ---------------------------------------------------------------------------


def _seed_turns(scan_dir: Path, turns: list[dict[str, object]]) -> None:
    """Write the given turn dicts to ``memory.jsonl`` verbatim (file order)."""
    lines: list[str] = []
    for i, turn in enumerate(turns):
        record = {
            "timestamp": f"2026-05-27T12:{30 + i:02d}:00+00:00",
            "record_type": "reflection",
            "payload": {"agent": turn.get("agent", ""), "content": json.dumps(turn)},
        }
        lines.append(json.dumps(record))
    (scan_dir / "memory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _turn(*, turn_no: int, verdict: str, probe_id: str = "PROBE-001") -> dict[str, object]:
    return {
        "agent": "goal-hijack-agent",
        "asi_category": "ASI01",
        "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
        "turn": turn_no,
        "strategy": "crescendo",
        "prompt": f"attacker prompt turn {turn_no}",
        "target_response": f"target response turn {turn_no}",
        "verdict": verdict,
        "confidence": 0.5 + 0.1 * turn_no,
        "reasoning": f"judge reasoning turn {turn_no}",
        "seed_id": probe_id,
        "attacker_refused": False,
    }


def test_finding_ctx_anchors_fields_to_the_flipping_turn(store: ScanStore) -> None:
    """The exchange that flipped the attack (first ``fail`` turn) supplies
    the top-level prompt / response / verdict / reasoning — they must all
    describe the SAME turn, not turn 1's defended exchange under an
    EXPLOITED verdict (the operator's "values don't look correct" bug).
    """
    from agent_guardian.server.dashboard_view import build_finding_slideover_ctx

    scan = _make_scan()
    scan_dir = _persist(store, scan)
    # Turn 1 defended, turn 2 defended, turn 3 EXPLOITED — and written in a
    # scrambled file order to prove the builder sorts by turn.
    _seed_turns(
        scan_dir,
        [
            _turn(turn_no=3, verdict="fail"),
            _turn(turn_no=1, verdict="pass"),
            _turn(turn_no=2, verdict="pass"),
        ],
    )
    finding = next(f for f in scan.findings if f.id == "f-crit-1")
    ctx = build_finding_slideover_ctx(finding, scan_dir=scan_dir)

    # Representative = the flipping (turn 3) exchange — all four fields agree.
    # Judge v2 (M0) — a successful finding rolls up to "exploited" (legacy
    # "fail" maps onto it) for the header pill.
    assert ctx["verdict"] == "exploited"
    assert ctx["prompt"] == "attacker prompt turn 3"
    assert ctx["target_response"] == "target response turn 3"
    assert ctx["reasoning"] == "judge reasoning turn 3"
    assert ctx["turn"] == 3

    # Conversation is in turn order regardless of file order.
    convo = ctx["conversation"]
    assert [t["turn_no"] for t in convo] == [1, 2, 3]
    # Per-turn verdicts normalize onto the current taxonomy (pass→defended,
    # fail→exploited) so the pill classes render correctly for legacy scans too.
    assert [t["verdict"] for t in convo] == ["defended", "defended", "exploited"]


def test_finding_ctx_single_turn_has_no_conversation(store: ScanStore) -> None:
    from agent_guardian.server.dashboard_view import build_finding_slideover_ctx

    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_turns(scan_dir, [_turn(turn_no=1, verdict="fail")])
    finding = next(f for f in scan.findings if f.id == "f-crit-1")
    ctx = build_finding_slideover_ctx(finding, scan_dir=scan_dir)
    assert ctx["conversation"] == []
    assert ctx["prompt"] == "attacker prompt turn 1"
