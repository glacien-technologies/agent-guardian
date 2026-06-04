"""Per-probe JSONL log writer (core/recon_probe_log.py)."""

from __future__ import annotations

import json
from pathlib import Path

from agent_guardian.core.recon_probe_log import ProbeLog, ProbeLogRecord


def test_record_to_dict_keeps_required_drops_none_optionals() -> None:
    rec = ProbeLogRecord(
        probe_id="probe-deadbeef",
        seq=0,
        band="audit",
        intent="action-probe-0",
        prompt="hi",
        session=None,
    )
    d = rec.to_dict()
    assert d == {
        "probe_id": "probe-deadbeef",
        "seq": 0,
        "band": "audit",
        "intent": "action-probe-0",
        "prompt": "hi",
        "session": None,
        "signals_observed": {},
    }
    # Optional keys absent when None.
    for key in ("response_envelope", "response_ref", "latency_ms", "novelty_decision", "error"):
        assert key not in d


def test_record_to_dict_includes_present_optionals() -> None:
    rec = ProbeLogRecord(
        probe_id="probe-1",
        seq=2,
        band="audit",
        intent="memory-plant",
        prompt="remember X",
        session="s-1",
        response_envelope={"text": "ok"},
        signals_observed={"tool_names": ["t"]},
        latency_ms=4.0,
        error="[target call failed: TimeoutError]",
    )
    d = rec.to_dict()
    assert d["response_envelope"] == {"text": "ok"}
    assert d["latency_ms"] == 4.0
    assert d["error"].startswith("[target call failed:")
    assert d["signals_observed"] == {"tool_names": ["t"]}


def test_next_seq_is_monotonic(tmp_path: Path) -> None:
    log = ProbeLog(tmp_path / "recon_probes.jsonl")
    assert [log.next_seq() for _ in range(3)] == [0, 1, 2]


def test_record_writes_one_jsonl_line_per_call(tmp_path: Path) -> None:
    path = tmp_path / "recon_probes.jsonl"
    log = ProbeLog(path)
    r0 = log.record(band="audit", intent="action-probe-0", prompt="p0", session=None)
    r1 = log.record(
        band="audit",
        intent="action-probe-1",
        prompt="p1",
        session="s",
        signals_observed={"tool_names": ["x"]},
    )
    log.close()

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["seq"] == 0
    assert parsed[1]["seq"] == 1
    assert parsed[0]["intent"] == "action-probe-0"
    assert parsed[1]["signals_observed"] == {"tool_names": ["x"]}
    # Returned records carry generated probe ids.
    assert r0.probe_id.startswith("probe-") and r1.probe_id.startswith("probe-")
    assert r0.seq == 0 and r1.seq == 1


def test_record_flushes_before_close_so_reader_sees_committed_bytes(tmp_path: Path) -> None:
    path = tmp_path / "recon_probes.jsonl"
    log = ProbeLog(path)
    log.record(band="audit", intent="i", prompt="p", session=None)
    # Flush happens inside record() -> readable without closing.
    assert path.read_text(encoding="utf-8").strip() != ""
    log.close()


def test_close_is_idempotent(tmp_path: Path) -> None:
    log = ProbeLog(tmp_path / "recon_probes.jsonl")
    log.record(band="audit", intent="i", prompt="p", session=None)
    log.close()
    log.close()  # no raise


def test_record_swallows_oserror(tmp_path: Path) -> None:
    # Point the log at a directory path so open("a") raises OSError; record
    # must still return a record and not propagate.
    log = ProbeLog(tmp_path)  # tmp_path is a directory
    rec = log.record(band="audit", intent="i", prompt="p", session=None)
    assert rec.seq == 0
    assert isinstance(rec, ProbeLogRecord)


def test_for_scan_dir_targets_sibling_file(tmp_path: Path) -> None:
    log = ProbeLog.for_scan_dir(tmp_path)
    log.record(band="audit", intent="i", prompt="p", session=None)
    log.close()
    assert (tmp_path / "recon_probes.jsonl").is_file()
