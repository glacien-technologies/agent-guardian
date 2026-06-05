"""Unit tests for the deeper recon signals surfaced by ``_assemble_recon_summary``.

The recon panel view-model now carries the evidence-grounded recon fields
(guardrail posture, confirmation requirement, observed data exposure,
behavioural flags, tool descriptions, capability-audit coverage ledger, and
probe count) read from the latest ``record_type=fingerprint`` line in a scan's
``memory.jsonl``. These pin that they round-trip from disk into the dict the
``_recon_panel.html`` template consumes — and that an OLD record lacking them
still produces safe defaults.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.server.dashboard_view import _assemble_recon_summary


def _write_fingerprint(scan_dir: Path, payload: dict[str, object]) -> None:
    scan_dir.mkdir(parents=True, exist_ok=True)
    rec = {"record_type": "fingerprint", "payload": payload}
    (scan_dir / "memory.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")


def test_recon_summary_surfaces_deep_fields(tmp_path: Path) -> None:
    payload = {
        "mode": "http",
        "ref": "https://x.example/chat",
        "has_tools": True,
        "declared_tools": ["refund_payment", "get_balance"],
        "guardrail_posture": "weak",
        "requires_confirmation": False,
        "data_exposure": ["returns balances without verification"],
        "behavioral_flags": ["no refusals observed"],
        "touches_pii": True,
        "tool_descriptions": {"get_balance": "look up a balance"},
        "recon_coverage": {"purpose": "confirmed", "tools": "partial"},
        "recon_probe_count": 12,
    }
    _write_fingerprint(tmp_path, payload)

    summary = _assemble_recon_summary(tmp_path)
    assert summary["has_data"] is True
    assert summary["guardrail_posture"] == "weak"
    assert summary["requires_confirmation"] is False
    assert summary["data_exposure"] == ["returns balances without verification"]
    assert summary["behavioral_flags"] == ["no refusals observed"]
    assert summary["touches_pii"] is True
    assert summary["tool_descriptions"] == {"get_balance": "look up a balance"}
    assert summary["recon_coverage"] == {"purpose": "confirmed", "tools": "partial"}
    assert summary["recon_probe_count"] == 12


def test_recon_summary_old_record_defaults(tmp_path: Path) -> None:
    """An OLD fingerprint record lacking the new keys yields safe defaults."""
    payload = {
        "mode": "http",
        "ref": "https://x.example/chat",
        "has_tools": True,
        "declared_tools": ["search"],
    }
    _write_fingerprint(tmp_path, payload)

    summary = _assemble_recon_summary(tmp_path)
    assert summary["has_data"] is True
    assert summary["guardrail_posture"] == ""
    assert summary["requires_confirmation"] is None
    assert summary["data_exposure"] == []
    assert summary["behavioral_flags"] == []
    assert summary["tool_descriptions"] == {}
    assert summary["recon_coverage"] == {}
    assert summary["recon_probe_count"] == 0
