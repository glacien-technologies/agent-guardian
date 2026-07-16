"""Issue #76 (D2) — signed forensic manifest over the scan's evidence trail."""

from __future__ import annotations

import hashlib
import io
import json
import logging
from pathlib import Path

from agent_guardian import logging_setup
from agent_guardian.reports.forensic_manifest import (
    FORENSIC_MANIFEST_SCHEMA,
    build_forensic_manifest,
    write_forensic_manifest,
)
from agent_guardian.server.partial_scan import (
    detach_jsonl_log_handler,
    install_jsonl_log_handler,
)


def _seed_scan_dir(tmp_path: Path) -> Path:
    d = tmp_path / "scans" / "cli-x"
    (d / "probe").mkdir(parents=True)
    (d / "run.log").write_text("turn 1 ...\n", encoding="utf-8")
    (d / "memory.jsonl").write_text('{"record_type":"reflection"}\n', encoding="utf-8")
    (d / "report.json").write_text("{}", encoding="utf-8")
    (d / "probe" / "goal-hijack-agent.json").write_text('{"turns":[]}', encoding="utf-8")
    return d


def test_manifest_hashes_every_forensic_file(tmp_path: Path) -> None:
    d = _seed_scan_dir(tmp_path)
    m = build_forensic_manifest(d, "cli-x", "2026-06-07T00:00:00Z")
    assert m["schema"] == FORENSIC_MANIFEST_SCHEMA
    assert m["algorithm"] == "sha256"
    assert set(m["files"]) == {
        "run.log",
        "memory.jsonl",
        "report.json",
        "probe/goal-hijack-agent.json",
    }
    # digest matches a direct hash of the file
    expect = hashlib.sha256((d / "run.log").read_bytes()).hexdigest()
    assert m["files"]["run.log"]["sha256"] == expect


def test_manifest_is_signed_and_written(tmp_path: Path) -> None:
    d = _seed_scan_dir(tmp_path)
    path = write_forensic_manifest(d, "cli-x", "2026-06-07T00:00:00Z")
    assert path.name == "forensic_manifest.json"
    doc = json.loads(path.read_text())
    assert "signatures" in doc  # Ed25519 + HMAC block from sign_payload
    assert doc["files"]["report.json"]["sha256"]


def test_manifest_detects_tampering(tmp_path: Path) -> None:
    d = _seed_scan_dir(tmp_path)
    m1 = build_forensic_manifest(d, "cli-x", "2026-06-07T00:00:00Z")
    # an attacker edits run.log after the scan
    (d / "run.log").write_text("turn 1 ... [REDACTED THE EXPLOIT]\n", encoding="utf-8")
    m2 = build_forensic_manifest(d, "cli-x", "2026-06-07T00:00:00Z")
    assert m1["files"]["run.log"]["sha256"] != m2["files"]["run.log"]["sha256"]


def test_jointly_detached_log_digests_stay_valid_after_later_logs(tmp_path: Path) -> None:
    d = _seed_scan_dir(tmp_path)
    console = io.StringIO()
    logging_setup.configure_logging(level="WARNING", stream=console, force=True)
    event_log_handler = install_jsonl_log_handler(d)
    run_log_handler = logging_setup.attach_run_log_file(d / "run.log")
    root = logging.getLogger()
    console_handler = next(handler for handler in root.handlers if handler is not event_log_handler)
    assert event_log_handler.level == logging.WARNING
    assert console_handler.level == logging.WARNING
    assert run_log_handler.level == logging.DEBUG
    log = logging.getLogger("agent_guardian.test.forensic_seal")
    try:
        log.warning("late completion and gate evaluation")
        if event_log_handler.level > logging.INFO:
            event_log_handler.setLevel(logging.INFO)
        log.info("forensic seal: run.log and events.jsonl complete")
        logging_setup.detach_run_log_file(run_log_handler)
        detach_jsonl_log_handler(event_log_handler)
        manifest_path = write_forensic_manifest(d, "cli-x", "2026-06-07T00:00:00Z")
        log.warning("terminal-only-after-manifest")
    finally:
        logging_setup.detach_run_log_file(run_log_handler)
        detach_jsonl_log_handler(event_log_handler)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for relative, record in manifest["files"].items():
        actual = hashlib.sha256((d / relative).read_bytes()).hexdigest()
        assert record["sha256"] == actual
    run_log = (d / "run.log").read_text(encoding="utf-8")
    events_log = (d / "events.jsonl").read_text(encoding="utf-8")
    for log_text in (run_log, events_log):
        assert "late completion and gate evaluation" in log_text
        assert "forensic seal: run.log and events.jsonl complete" in log_text
        assert "terminal-only-after-manifest" not in log_text
    assert console_handler.level == logging.WARNING
    assert "forensic seal: run.log and events.jsonl complete" not in console.getvalue()
    assert "late completion and gate evaluation" in console.getvalue()
    assert "terminal-only-after-manifest" in console.getvalue()
