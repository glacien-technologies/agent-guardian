"""Authoritative per-probe JSON export persisted under ``scans/<id>/probe/``.

Operator ask: persist the full event/turn record for every probe to disk as
JSON, with NO truncation — the dashboard's log preview elides long prompts /
responses (``…``), so the on-disk export must be the authoritative, complete
record (verbatim prompts, full target responses, full judge reasoning) plus the
worst-case rolled-up verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.server.probe_export import build_probe_exports, write_probe_exports

# A deliberately long response so we can assert it is NOT truncated anywhere.
_LONG_RESPONSE = "Account 2002 ledger dump: " + ("entry " * 400) + "END_OF_LEDGER"


def _turn(agent: str, asi: str, seed_id: str, turn: int, verdict: str, response: str) -> dict:
    return {
        "agent": agent,
        "asi_category": asi,
        "turn": turn,
        "seed_id": seed_id,
        "strategy": "pair",
        "prompt": f"attacker prompt for turn {turn}",
        "target_response": response,
        "verdict": verdict,
        "confidence": 1.0,
        "reasoning": f"judge reasoning for turn {turn}",
    }


def _reflection_line(turn_record: dict) -> str:
    return json.dumps(
        {
            "record_type": "reflection",
            "payload": {"content": json.dumps(turn_record)},
        }
    )


def _write_scan(tmp_path: Path) -> Path:
    scan_dir = tmp_path / "cli-test"
    scan_dir.mkdir()
    turns = [
        _turn("identity-leak-agent", "ASI03", "ASI03-PII-001", 1, "defended", "I cannot do that."),
        _turn("identity-leak-agent", "ASI03", "ASI03-PII-001", 2, "info_leak", _LONG_RESPONSE),
        _turn("identity-leak-agent", "ASI03", "ASI03-PII-001", 3, "info_leak", "More leaked data."),
    ]
    (scan_dir / "memory.jsonl").write_text(
        "\n".join(_reflection_line(t) for t in turns) + "\n", encoding="utf-8"
    )
    # events.jsonl carries the (truncation-previewed) log + full reflection events.
    events = [
        {"kind": "agent_start", "agent": "identity-leak-agent", "asi": "ASI03", "seq": 1},
        {
            "kind": "log",
            "seq": 2,
            "payload": {"message": "[identity-leak-agent] probe ASI03-PII-001 | prompt …"},
        },
        {"kind": "agent_done", "agent": "identity-leak-agent", "payload": {"findings_count": 2}},
    ]
    (scan_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    return scan_dir


def test_build_groups_turns_by_agent_and_rolls_up_worst_verdict(tmp_path: Path) -> None:
    scan_dir = _write_scan(tmp_path)
    exports = build_probe_exports(scan_dir)
    # One entry per AGENT (not per probe id) — all of the agent's turns in one.
    assert "identity-leak-agent" in exports
    exp = exports["identity-leak-agent"]
    assert exp["agent"] == "identity-leak-agent"
    assert exp["asi_category"] == "ASI03"
    assert exp["turn_count"] == 3
    # Worst-case wins — a single info_leak turn is never hidden behind defended.
    assert exp["verdict"] == "info_leak"
    assert exp["best_evidence_turn"] == 2
    assert len(exp["turns"]) == 3
    # Turns are ordered by turn number, each carrying its own number + probe id.
    assert [t["turn"] for t in exp["turns"]] == [1, 2, 3]
    assert "ASI03-PII-001" in exp["probe_ids"]


def test_export_is_authoritative_untruncated(tmp_path: Path) -> None:
    scan_dir = _write_scan(tmp_path)
    exports = build_probe_exports(scan_dir)
    exp = exports["identity-leak-agent"]
    # The full long response must appear verbatim — nothing elided.
    leaked = next(t for t in exp["turns"] if t["turn"] == 2)
    assert leaked["target_response"] == _LONG_RESPONSE
    assert "…" not in json.dumps(leaked)


def test_write_persists_one_file_per_agent(tmp_path: Path) -> None:
    scan_dir = _write_scan(tmp_path)
    probe_dir = write_probe_exports(scan_dir)
    assert probe_dir == scan_dir / "probe"
    f = probe_dir / "identity-leak-agent.json"
    assert f.is_file()
    data = json.loads(f.read_text(encoding="utf-8"))
    assert data["verdict"] == "info_leak"
    assert data["turn_count"] == 3
    # Full response survived the round-trip to disk untruncated.
    assert _LONG_RESPONSE in f.read_text(encoding="utf-8")
    # Index lists the agent.
    index = json.loads((probe_dir / "index.json").read_text(encoding="utf-8"))
    agents = {row["agent"] for row in index["probes"]}
    assert "identity-leak-agent" in agents


def test_filename_is_filesystem_safe(tmp_path: Path) -> None:
    # Agent names are already safe; guard slashes anyway.
    scan_dir = tmp_path / "cli-fs"
    scan_dir.mkdir()
    tr = _turn(
        "fuzzing-agent", "ASI02", "ASI02-FUZZ-TYPE-01-mutant-fuzz", 1, "weakness_observed", "x"
    )
    (scan_dir / "memory.jsonl").write_text(_reflection_line(tr) + "\n", encoding="utf-8")
    probe_dir = write_probe_exports(scan_dir)
    assert (probe_dir / "fuzzing-agent.json").is_file()


def test_missing_scan_dir_is_safe(tmp_path: Path) -> None:
    assert build_probe_exports(tmp_path / "nope") == {}
    # write on an empty dir creates the probe dir with just an (empty) index.
    empty = tmp_path / "empty"
    empty.mkdir()
    probe_dir = write_probe_exports(empty)
    index = json.loads((probe_dir / "index.json").read_text(encoding="utf-8"))
    assert index["probes"] == []
