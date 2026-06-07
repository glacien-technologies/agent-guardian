"""`agent-guardian suite` CLI — validate / dry-run / summary surfaces."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_guardian.cli import app

runner = CliRunner()

_VALID = """
version: 1
suite:
  name: demo
defaults:
  model: gemini:gemini-2.5-flash
workloads:
  - name: a
    endpoint: https://a.test/agent
  - name: b
    target: pkg.mod:run
"""


def test_suite_registered_on_main_app() -> None:
    result = runner.invoke(app, ["suite", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output
    assert "validate" in result.output


def test_validate_ok(tmp_path: Path) -> None:
    p = tmp_path / "s.yaml"
    p.write_text(_VALID, encoding="utf-8")
    result = runner.invoke(app, ["suite", "validate", str(p)])
    assert result.exit_code == 0
    assert "OK" in result.output
    assert "a" in result.output and "b" in result.output


def test_validate_rejects_bad_target(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(
        "version: 1\nsuite:\n  name: d\nworkloads:\n  - name: a\n    mode: fast\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["suite", "validate", str(p)])
    assert result.exit_code == 2
    assert "INVALID" in result.output


def test_dry_run_prints_resolved_scan_commands(tmp_path: Path) -> None:
    p = tmp_path / "s.yaml"
    p.write_text(_VALID, encoding="utf-8")
    result = runner.invoke(app, ["suite", "run", str(p), "--dry-run"])
    assert result.exit_code == 0
    assert "[a]" in result.output and "[b]" in result.output
    assert "--endpoint https://a.test/agent" in result.output
    assert "pkg.mod:run" in result.output
    assert "--no-serve" in result.output  # forced headless flag visible


def test_summary_reprints_prior_run(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "summary.json").write_text(
        json.dumps(
            {
                "workloads": [
                    {
                        "name": "a",
                        "status": "ok",
                        "exit_code": 0,
                        "scan_id": "cli-1",
                        "log_folder": "/s/cli-1",
                        "aivss": 41,
                        "band": "POOR",
                        "tier": "T2",
                        "findings_total": 3,
                        "findings_by_severity": {},
                        "refusal_rate": 0.0,
                        "authoritative": True,
                        "authority_caveats": [],
                        "reports": {},
                        "console_log": "/o/a.log",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["suite", "summary", str(out)])
    assert result.exit_code == 0
    assert "SUMMARY" in result.output
    assert "/s/cli-1" in result.output
