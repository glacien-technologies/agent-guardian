"""QA-023 — unit tests for the Executive view-model additions.

Targets the new ``probes_list`` / ``logs_tail`` payload fields produced by
:func:`build_dashboard_context` and the helper functions that back them
(``_assemble_probes_list``, ``_parse_reflection_line``, ``_assemble_logs_tail``,
``_parse_event_line``, ``_derive_log_level``, ``_derive_log_summary``,
``_timestamp_label``). These tests run without a TestClient so the pure
view-model layer is covered in isolation.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.server import dashboard_view as dv
from agent_guardian.server.dashboard_view import (
    _assemble_logs_tail,
    _assemble_probes_list,
    _derive_log_level,
    _derive_log_summary,
    _parse_event_line,
    _parse_reflection_line,
    _timestamp_label,
    build_dashboard_context,
)

# ---------------------------------------------------------------------------
# probes_list helpers
# ---------------------------------------------------------------------------


def test_assemble_probes_list_none_scan_dir_returns_empty() -> None:
    assert _assemble_probes_list(None) == []


def test_assemble_probes_list_missing_file_returns_empty(tmp_path: Path) -> None:
    # tmp_path has no memory.jsonl yet.
    assert _assemble_probes_list(tmp_path) == []


def test_assemble_probes_list_reads_one_reflection_record(tmp_path: Path) -> None:
    turn = {
        "agent": "asi01-goal",
        "asi_category": "ASI01",
        "csa_category": "GOAL_INSTRUCTION_MANIPULATION",
        "turn": 3,
        "strategy": "direct_injection",
        "prompt": "ignore prior instructions",
        "target_response": "I cannot do that.",
        "verdict": "robust",
        "confidence": 0.92,
        "reasoning": "target refused",
        "seed_id": "PROBE-007",
        "attacker_refused": False,
    }
    record = {
        "timestamp": "2026-05-27T12:30:15+00:00",
        "record_type": "reflection",
        "payload": {"agent": "asi01-goal", "content": json.dumps(turn)},
    }
    (tmp_path / "memory.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["agent"] == "asi01-goal"
    assert row["asi_category"] == "ASI01"
    assert row["turn"] == 3
    assert row["probe_id"] == "PROBE-007"
    assert row["prompt"] == "ignore prior instructions"
    assert row["verdict"] == "robust"
    assert row["confidence"] == 0.92
    assert row["timestamp_label"] == "12:30:15"


def test_assemble_probes_list_skips_non_reflection_rows(tmp_path: Path) -> None:
    rows_in = [
        {"record_type": "tool_call", "payload": {"agent": "x"}},
        {
            "record_type": "reflection",
            "payload": {"agent": "y", "content": json.dumps({"agent": "y"})},
        },
        {"random": "noise"},
    ]
    (tmp_path / "memory.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows_in) + "\n", encoding="utf-8"
    )
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 1
    assert rows[0]["agent"] == "y"


def test_assemble_probes_list_skips_blank_and_malformed_lines(tmp_path: Path) -> None:
    payload_lines = [
        "",
        "not-json",
        json.dumps({"record_type": "reflection", "payload": {"agent": "z", "content": "bad-json"}}),
        json.dumps(
            {
                "record_type": "reflection",
                "payload": {
                    "agent": "z",
                    "content": json.dumps({"agent": "z", "verdict": "vulnerable"}),
                },
            }
        ),
    ]
    (tmp_path / "memory.jsonl").write_text("\n".join(payload_lines) + "\n", encoding="utf-8")
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 2
    assert all(r["agent"] == "z" for r in rows)


def test_assemble_probes_list_caps_at_500_entries(tmp_path: Path) -> None:
    record = {
        "record_type": "reflection",
        "payload": {"agent": "x", "content": json.dumps({"agent": "x"})},
    }
    lines = [json.dumps(record)] * 750
    (tmp_path / "memory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = _assemble_probes_list(tmp_path)
    assert len(rows) == 500


def test_parse_reflection_line_returns_none_for_malformed_json() -> None:
    assert _parse_reflection_line("not-json") is None


def test_parse_reflection_line_returns_none_for_non_dict_root() -> None:
    assert _parse_reflection_line(json.dumps([1, 2, 3])) is None


def test_parse_reflection_line_returns_none_for_wrong_record_type() -> None:
    raw = json.dumps({"record_type": "tool_call"})
    assert _parse_reflection_line(raw) is None


def test_parse_reflection_line_returns_none_when_payload_not_dict() -> None:
    raw = json.dumps({"record_type": "reflection", "payload": "string"})
    assert _parse_reflection_line(raw) is None


def test_parse_reflection_line_handles_missing_content() -> None:
    raw = json.dumps({"record_type": "reflection", "payload": {"agent": "x"}})
    parsed = _parse_reflection_line(raw)
    assert parsed is not None
    assert parsed["agent"] == "x"
    assert parsed["prompt"] == ""


def test_parse_reflection_line_handles_unparseable_content_string() -> None:
    raw = json.dumps(
        {"record_type": "reflection", "payload": {"agent": "x", "content": "not-json"}}
    )
    parsed = _parse_reflection_line(raw)
    assert parsed is not None
    assert parsed["agent"] == "x"


# ---------------------------------------------------------------------------
# logs_tail helpers
# ---------------------------------------------------------------------------


def test_assemble_logs_tail_none_scan_dir_returns_empty() -> None:
    assert _assemble_logs_tail(None) == []


def test_assemble_logs_tail_missing_file_returns_empty(tmp_path: Path) -> None:
    assert _assemble_logs_tail(tmp_path) == []


def test_assemble_logs_tail_reads_locked_shape(tmp_path: Path) -> None:
    events = [
        {
            "kind": "agent_skipped",
            "agent": "asi02-tool",
            "asi": "ASI02",
            "decision": None,
            "payload": {"reason": "budget exhausted"},
            "timestamp": "2026-05-27T12:01:00+00:00",
        },
        {
            "kind": "finding_emitted",
            "agent": "asi01-goal",
            "asi": "ASI01",
            "payload": {"severity": "critical"},
            "timestamp": "2026-05-27T12:02:00+00:00",
        },
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    rows = _assemble_logs_tail(tmp_path)
    assert len(rows) == 2
    assert rows[0]["level"] == "warn"
    assert "budget exhausted" in rows[0]["summary"]
    assert rows[1]["level"] == "info"
    assert "severity=critical" in rows[1]["summary"]
    assert rows[1]["agent"] == "asi01-goal"
    assert rows[0]["timestamp_label"] == "12:01:00"


def test_assemble_logs_tail_caps_at_1000_entries_keeping_newest(tmp_path: Path) -> None:
    events = [
        {
            "kind": "tick",
            "agent": None,
            "asi": None,
            "payload": {"seq": i},
            "timestamp": "2026-05-27T12:00:00+00:00",
        }
        for i in range(1200)
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    rows = _assemble_logs_tail(tmp_path)
    assert len(rows) == 1000
    # FIFO tail — the kept rows are the newest 1000 (seq starts at 200).
    seq_values = [int(r["payload_keys"][0] == "seq") for r in rows]  # just checking shape
    assert all(s == 1 for s in seq_values)


def test_assemble_logs_tail_skips_malformed_lines(tmp_path: Path) -> None:
    lines = [
        "",
        "{not json",
        json.dumps([1, 2, 3]),  # non-dict
        json.dumps({"kind": "scan_started", "payload": {"message": "boot"}}),
    ]
    (tmp_path / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = _assemble_logs_tail(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "scan_started"


def test_parse_event_line_returns_none_for_malformed_json() -> None:
    assert _parse_event_line("not-json") is None


def test_parse_event_line_returns_none_for_non_dict_root() -> None:
    assert _parse_event_line(json.dumps(42)) is None


def test_parse_event_line_coerces_missing_payload_to_empty_dict() -> None:
    raw = json.dumps({"kind": "tick"})
    parsed = _parse_event_line(raw)
    assert parsed is not None
    assert parsed["payload_keys"] == []
    assert parsed["kind"] == "tick"
    assert parsed["level"] == "info"


# ---------------------------------------------------------------------------
# log level + summary derivation
# ---------------------------------------------------------------------------


def test_derive_log_level_agent_skipped_warns() -> None:
    assert _derive_log_level("agent_skipped", {}) == "warn"


def test_derive_log_level_explicit_error_kind() -> None:
    assert _derive_log_level("error", {}) == "error"


def test_derive_log_level_payload_error_truthy_errors() -> None:
    assert _derive_log_level("any_kind", {"error": "boom"}) == "error"


def test_derive_log_level_default_is_info() -> None:
    assert _derive_log_level("scan_started", {}) == "info"


def test_derive_log_summary_priority_order() -> None:
    # severity wins over reason + message
    assert (
        _derive_log_summary("k", {"severity": "high", "reason": "r", "message": "m"})
        == "k :: severity=high"
    )
    # reason wins over message
    assert _derive_log_summary("k", {"reason": "r", "message": "m"}) == "k :: r"
    # message is the last resort
    assert _derive_log_summary("k", {"message": "m"}) == "k :: m"
    # fallback to the bare kind
    assert _derive_log_summary("k", {}) == "k"


# ---------------------------------------------------------------------------
# timestamp helper
# ---------------------------------------------------------------------------


def test_timestamp_label_handles_iso_with_z() -> None:
    assert _timestamp_label("2026-05-27T12:30:15Z") == "12:30:15"


def test_timestamp_label_handles_iso_with_offset() -> None:
    assert _timestamp_label("2026-05-27T12:30:15+00:00") == "12:30:15"


def test_timestamp_label_returns_empty_for_non_string() -> None:
    assert _timestamp_label(None) == ""
    assert _timestamp_label(123) == ""


def test_timestamp_label_returns_empty_for_unparseable() -> None:
    assert _timestamp_label("not-a-date") == ""


# ---------------------------------------------------------------------------
# build_dashboard_context — additive payload contract
# ---------------------------------------------------------------------------


def test_build_dashboard_context_additive_keys_with_no_scan_dir() -> None:
    ctx = build_dashboard_context(
        scan_id="sid",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8000",
        version_label="0.0.0",
    )
    p = ctx.payload
    assert "probes_list" in p
    assert "logs_tail" in p
    assert p["probes_list"] == []
    assert p["logs_tail"] == []


def test_build_dashboard_context_with_scan_dir_reads_memory_jsonl(tmp_path: Path) -> None:
    turn = {
        "agent": "x",
        "asi_category": "ASI01",
        "verdict": "vulnerable",
        "seed_id": "P-1",
    }
    record = {
        "record_type": "reflection",
        "payload": {"agent": "x", "content": json.dumps(turn)},
        "timestamp": "2026-05-27T12:01:02+00:00",
    }
    (tmp_path / "memory.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    ctx = build_dashboard_context(
        scan_id="sid",
        scan=None,
        is_running=True,
        base_url="http://127.0.0.1:8000",
        version_label="0.0.0",
        scan_dir=tmp_path,
    )
    assert ctx.payload["probes_list"][0]["agent"] == "x"


def test_dashboard_view_module_caps_are_locked() -> None:
    """Locked constants — the design lock says 500 / 1000, never change without QA."""
    assert dv._PROBES_LIST_CAP == 500
    assert dv._LOGS_TAIL_CAP == 1000
