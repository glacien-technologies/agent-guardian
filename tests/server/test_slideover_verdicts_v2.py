"""Judge v2 (M5 / Stage D) — slide-over + probes-table render for v2 verdicts.

Renders the shared ``_slideover.html`` body (via ``/scan/<id>/probe?group=``)
and the dashboard page (``_probes_table.html``) for the six v2 verdicts and a
verify turn, asserting:

  * the new per-verdict pill classes (``exec-verdict-pill--<verdict>``) appear,
  * a VERIFY badge renders for a verify turn,
  * the run-result block + best-evidence turn + evaluator-attack marker render,
  * the verbatim judge Evidence span renders,
  * none of the six verdicts error the render.

Uses the existing server TestClient fixtures.
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
        id="cli-slideover-v2-001",
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
        created_at=datetime(2026, 6, 5, 12, 5, 0, tzinfo=UTC),
    )


def _persist(store: ScanStore, scan: Scan) -> Path:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return scan_dir


def _reflection(turn: dict[str, object]) -> str:
    record = {
        "timestamp": "2026-06-05T12:30:00+00:00",
        "record_type": "reflection",
        "payload": {"agent": turn["agent"], "content": json.dumps(turn)},
    }
    return json.dumps(record) + "\n"


SIX_VERDICTS = [
    "exploited",
    "info_leak",
    "weakness_observed",
    "needs_followup",
    "simulated_or_unverified",
    "defended",
]


def _seed_six_verdicts(scan_dir: Path) -> None:
    """One agent per verdict so the probes table renders all six pills."""
    lines = []
    for i, verdict in enumerate(SIX_VERDICTS, start=1):
        lines.append(
            _reflection(
                {
                    "agent": f"agent-{verdict}",
                    "asi_category": f"ASI0{i}",
                    "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
                    "turn": 1,
                    "strategy": "direct_injection",
                    "prompt": f"attacker prompt {verdict}",
                    "target_response": f"target response {verdict}",
                    "verdict": verdict,
                    "verdict_v2": verdict,
                    "confidence": 0.8,
                    "reasoning": f"reasoning for {verdict}",
                    "evidence": f"evidence span for {verdict}",
                    "seed_id": f"PROBE-{i}",
                }
            )
        )
    (scan_dir / "memory.jsonl").write_text("".join(lines), encoding="utf-8")


def test_probes_table_renders_all_six_verdict_pills(client: TestClient, store: ScanStore) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_six_verdicts(scan_dir)
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 200
    body = resp.text
    for verdict in SIX_VERDICTS:
        assert f"exec-verdict-pill--{verdict}" in body, f"missing pill class for {verdict}"
    # Human labels present too.
    for label in (
        "EXPLOITED",
        "INFO LEAK",
        "WEAKNESS",
        "NEEDS FOLLOW-UP",
        "UNVERIFIED",
        "DEFENDED",
    ):
        assert label in body, f"missing label {label!r}"


def _seed_verify_thread(scan_dir: Path) -> None:
    """A two-turn thread: a needs_followup attack turn + a verify turn that
    confirms an exploit, with an evaluator-attack flag and evidence span."""
    t1 = {
        "agent": "goal-hijack-agent",
        "asi_category": "ASI01",
        "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
        "turn": 1,
        "max_turns": 3,
        "strategy": "direct_injection",
        "prompt": "initial attack prompt",
        "target_response": "ambiguous response",
        "verdict": "needs_followup",
        "verdict_v2": "needs_followup",
        "confidence": 0.4,
        "reasoning": "engaged but not yet observable",
        "seed_id": "PROBE-V",
        "intent": "attack",
        "verify": False,
    }
    t2 = {
        "agent": "goal-hijack-agent",
        "asi_category": "ASI01",
        "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
        "turn": 2,
        "max_turns": 3,
        "strategy": "direct_injection",
        "prompt": "drill-down verification probe",
        "target_response": "leaked: SECRET-TOKEN-123",
        "verdict": "exploited",
        "verdict_v2": "exploited",
        "confidence": 0.95,
        "reasoning": "confirmed observable exploit",
        "evidence": "SECRET-TOKEN-123",
        "evaluator_attack": True,
        "seed_id": "PROBE-V",
        "intent": "verify",
        "verify": True,
    }
    (scan_dir / "memory.jsonl").write_text(_reflection(t1) + _reflection(t2), encoding="utf-8")


def test_group_slideover_renders_verify_badge_and_evidence_and_run_result(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_verify_thread(scan_dir)
    resp = client.get(f"/scan/{scan.id}/probe?group=goal-hijack-agent")
    assert resp.status_code == 200
    body = resp.text
    # VERIFY badge + verification-probe header for the verify turn.
    assert "VERIFY" in body
    assert "VERIFICATION PROBE" in body
    # Evaluator-attack marker for the manipulated turn.
    assert "evaluator-attack" in body
    # Verbatim judge evidence span surfaced.
    assert "SECRET-TOKEN-123" in body
    assert "Evidence" in body
    # Run-result block: strongest-evidence turn + run verdict pill.
    assert "Run result" in body
    assert "strongest evidence: turn 2" in body or "turn 2" in body
    assert "exec-verdict-pill--exploited" in body


def test_each_verdict_group_slideover_renders_without_error(
    client: TestClient, store: ScanStore
) -> None:
    scan = _make_scan()
    scan_dir = _persist(store, scan)
    _seed_six_verdicts(scan_dir)
    for verdict in SIX_VERDICTS:
        resp = client.get(f"/scan/{scan.id}/probe?group=agent-{verdict}")
        assert resp.status_code == 200, f"{verdict} group slideover errored"
        body = resp.text
        # Per-turn pill class for this verdict present in the conversation.
        assert f"exec-verdict-pill--{verdict}" in body
        # Evidence span rendered.
        assert f"evidence span for {verdict}" in body
