"""Issue #76 (D2) — signed forensic manifest over the scan's evidence trail."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from agent_guardian import logging_setup
from agent_guardian.reports.forensic_manifest import (
    FORENSIC_MANIFEST_SCHEMA,
    build_forensic_manifest,
    write_forensic_manifest,
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


def test_detached_run_log_digest_stays_valid_after_later_logs(tmp_path: Path) -> None:
    d = _seed_scan_dir(tmp_path)
    logging_setup.configure_logging(level="DEBUG", force=True)
    handler = logging_setup.attach_run_log_file(d / "run.log")
    log = logging.getLogger("agent_guardian.test.forensic_seal")
    log.info("forensic seal: run.log complete")
    logging_setup.detach_run_log_file(handler)
    manifest_path = write_forensic_manifest(d, "cli-x", "2026-06-07T00:00:00Z")
    log.info("terminal-only-after-manifest")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for relative, record in manifest["files"].items():
        actual = hashlib.sha256((d / relative).read_bytes()).hexdigest()
        assert record["sha256"] == actual
    assert "terminal-only-after-manifest" not in (d / "run.log").read_text(encoding="utf-8")
