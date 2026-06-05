"""Judge v2 (M5 / Stage D) — dashboard view-model verdict rendering.

Covers the six-verdict label map, the verify-turn flag, the strongest-evidence
run-result view-model (run_verdict / best_evidence_turn / evaluator_attack), and
the per-turn evidence / evaluator-attack signals — all assembled by
``server/dashboard_view.py`` without touching FastAPI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_guardian.server.dashboard_view import (
    _assemble_probe_groups,
    _assemble_probes_list,
    _conversation_turns,
    _run_result_view,
    _verdict_label,
    build_probe_group_slideover_ctx,
)


# --------------------------------------------------------------------------
# 1. Six-verdict label map (+ legacy normalize-through).
# --------------------------------------------------------------------------
def test_verdict_label_covers_all_six_v2_verdicts() -> None:
    assert _verdict_label("exploited") == "EXPLOITED"
    assert _verdict_label("info_leak") == "INFO LEAK"
    assert _verdict_label("weakness_observed") == "WEAKNESS"
    assert _verdict_label("needs_followup") == "NEEDS FOLLOW-UP"
    assert _verdict_label("simulated_or_unverified") == "UNVERIFIED"
    assert _verdict_label("defended") == "DEFENDED"


def test_verdict_label_legacy_maps_through_normalize() -> None:
    # Legacy pass/fail/inconclusive normalize onto the v2 taxonomy.
    assert _verdict_label("fail") == "EXPLOITED"
    assert _verdict_label("pass") == "DEFENDED"
    assert _verdict_label("inconclusive") == "NEEDS FOLLOW-UP"
    # Case / whitespace tolerant.
    assert _verdict_label("  FAIL ") == "EXPLOITED"


def test_verdict_label_blank_is_pending() -> None:
    assert _verdict_label("") == "PENDING"
    assert _verdict_label("   ") == "PENDING"


# --------------------------------------------------------------------------
# 2. Verify-turn flag threads into the per-turn view-model.
# --------------------------------------------------------------------------
def _turn(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "agent": "goal-hijack-agent",
        "asi_category": "ASI01",
        "turn": 1,
        "prompt": "p",
        "target_response": "r",
        "verdict": "needs_followup",
        "confidence": 0.5,
        "reasoning": "why",
        "verify": False,
        "evaluator_attack": False,
        "evidence": "",
    }
    base.update(over)
    return base


def test_conversation_turn_carries_verify_flag() -> None:
    turns = [
        _turn(turn=1, verdict="needs_followup", verify=False),
        _turn(turn=2, verdict="exploited", verify=True, evidence="leaked: secret-xyz"),
    ]
    convo = _conversation_turns(turns)
    assert convo[0]["verify"] is False
    assert convo[1]["verify"] is True
    assert convo[1]["evidence"] == "leaked: secret-xyz"


def test_conversation_turn_carries_evaluator_attack_flag() -> None:
    turns = [_turn(turn=1, evaluator_attack=True)]
    convo = _conversation_turns(turns)
    assert convo[0]["evaluator_attack"] is True


# --------------------------------------------------------------------------
# 3. Run-result view-model (strongest evidence + best turn + eval-attack).
# --------------------------------------------------------------------------
def test_run_result_view_picks_strongest_evidence_turn() -> None:
    turns = [
        _turn(turn=1, verdict="defended", confidence=0.9),
        _turn(turn=2, verdict="exploited", confidence=0.95),
        _turn(turn=3, verdict="weakness_observed", confidence=0.4),
    ]
    rr = _run_result_view(turns)
    assert rr["has_run_result"] is True
    assert rr["run_verdict"] == "exploited"
    assert rr["run_verdict_label"] == "EXPLOITED"
    # best_evidence_turn is the WINNING record's own turn number, not the index.
    assert rr["best_evidence_turn"] == 2
    assert rr["run_confidence_pct"] == "95%"


def test_run_result_view_surfaces_evaluator_attack() -> None:
    turns = [
        _turn(turn=1, verdict="defended"),
        _turn(turn=2, verdict="needs_followup", evaluator_attack=True),
    ]
    rr = _run_result_view(turns)
    assert rr["evaluator_attack"] is True


def test_run_result_view_omitted_for_verdictless_thread() -> None:
    # Recon-style turns carry no verdict — omit the row entirely.
    turns = [
        {"agent": "recon-agent", "turn": 0, "verdict": "", "verdict_v2": ""},
        {"agent": "recon-agent", "turn": 0, "verdict": "", "verdict_v2": ""},
    ]
    rr = _run_result_view(turns)
    assert rr["has_run_result"] is False


def test_run_result_view_empty_for_no_turns() -> None:
    assert _run_result_view([])["has_run_result"] is False


# --------------------------------------------------------------------------
# 4. Probe-group assembly threads run_result; recon omits it.
# --------------------------------------------------------------------------
def _write_reflection(fh: Any, turn: dict[str, Any]) -> None:
    record = {
        "timestamp": "2026-06-05T12:00:00+00:00",
        "record_type": "reflection",
        "payload": {"agent": turn.get("agent", ""), "content": json.dumps(turn)},
    }
    fh.write(json.dumps(record) + "\n")


def test_probe_groups_carry_run_result(tmp_path: Path) -> None:
    mem = tmp_path / "memory.jsonl"
    with mem.open("w", encoding="utf-8") as fh:
        _write_reflection(
            fh,
            {
                "agent": "goal-hijack-agent",
                "asi_category": "ASI01",
                "turn": 1,
                "verdict": "needs_followup",
                "confidence": 0.4,
                "seed_id": "PROBE-1",
            },
        )
        _write_reflection(
            fh,
            {
                "agent": "goal-hijack-agent",
                "asi_category": "ASI01",
                "turn": 2,
                "verdict": "exploited",
                "verdict_v2": "exploited",
                "confidence": 0.92,
                "evaluator_attack": True,
                "evidence": "the verbatim leak",
                "seed_id": "PROBE-1",
            },
        )
    probes = _assemble_probes_list(tmp_path)
    groups = _assemble_probe_groups(probes)
    assert len(groups) == 1
    rr = groups[0]["run_result"]
    assert rr["has_run_result"] is True
    assert rr["run_verdict"] == "exploited"
    assert rr["best_evidence_turn"] == 2
    assert rr["evaluator_attack"] is True


def test_recon_group_omits_run_result(tmp_path: Path) -> None:
    mem = tmp_path / "memory.jsonl"
    with mem.open("w", encoding="utf-8") as fh:
        _write_reflection(
            fh,
            {"agent": "recon-agent", "asi_category": "", "turn": 0, "verdict": ""},
        )
    probes = _assemble_probes_list(tmp_path)
    groups = _assemble_probe_groups(probes)
    assert len(groups) == 1
    assert groups[0]["run_result"]["has_run_result"] is False
    assert groups[0]["verdict"] == "recon"


# --------------------------------------------------------------------------
# 5. Group slide-over ctx exposes the verify flag + run-result + evidence.
# --------------------------------------------------------------------------
def test_group_slideover_ctx_threads_verify_and_run_result(tmp_path: Path) -> None:
    turns = [
        _turn(turn=1, verdict="needs_followup", confidence=0.4, max_turns=3),
        _turn(
            turn=2,
            verdict="exploited",
            verdict_v2="exploited",
            confidence=0.95,
            verify=True,
            evidence="proof span",
            max_turns=3,
        ),
    ]
    ctx = build_probe_group_slideover_ctx(turns)
    # Run-result threaded.
    assert ctx["run_result"]["has_run_result"] is True
    assert ctx["run_result"]["run_verdict"] == "exploited"
    assert ctx["run_result"]["best_evidence_turn"] == 2
    # Conversation carries the verify badge + evidence on turn 2.
    convo = ctx["conversation"]
    assert convo[1]["verify"] is True
    assert convo[1]["evidence"] == "proof span"
