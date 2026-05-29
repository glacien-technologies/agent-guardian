"""Integration test for ``agent-guardian scan --contract`` (Stage 1B).

Runs a full stub swarm scan against a respx-mocked HTTP endpoint driven entirely
by a contract. Asserts that: a Scan is produced + persisted, an ``audit.jsonl``
provenance trail is written under the scan dir, and the SARIF report carries the
contract provenance (``contract_sha256``) + the RoE ``invocations`` block.

All LLM roles are pinned to ``--model stub`` so no network/keys are needed for
the swarm itself; only the *target* endpoint is mocked via respx.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from agent_guardian.cli import EXIT_OK, app

URL = "https://api.example.com/v1/chat"

# Egress is explicitly allowed so the swarm's target calls actually reach the
# mocked endpoint. Budgets are kept small so the stub scan stays fast.
_CONTRACT = """
version: 1
target:
  name: contract-scan-demo
  environment: staging
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
  session:
    mode: stateless
roe:
  authorization_ref: TICKET-42
  data_egress:
    allow_external: true
  budgets:
    max_tokens: 50000
    max_wallclock_minutes: 1
  rate:
    parallel_workers: 4
"""


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    # The first-run ethical banner is suppressed by a pre-seeded state file so
    # it does not interfere with output assertions.
    state_dir = tmp_path / ".agentguardian"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "state.json").write_text(
        json.dumps({"ethical_use_acknowledged": True}), encoding="utf-8"
    )


@respx.mock
def test_scan_contract_full_stub_run(runner: CliRunner, tmp_path: Path) -> None:
    # The target always replies the same benign text regardless of the prompt.
    respx.post(URL).mock(
        return_value=httpx.Response(200, json={"output": {"text": "I cannot help with that."}})
    )
    contract_path = tmp_path / "agentguardian.yaml"
    contract_path.write_text(_CONTRACT, encoding="utf-8")
    report_path = tmp_path / "report.sarif"

    result = runner.invoke(
        app,
        [
            "scan",
            "--contract",
            str(contract_path),
            "--model",
            "stub",
            "--no-tui",
            "--mode",
            "fast",
            "--output",
            "sarif",
            "--output-path",
            str(report_path),
            "--seed",
            "0",
        ],
    )

    assert result.exit_code == EXIT_OK, result.output
    assert "scan" in result.output and "done" in result.output

    # A SARIF report was written.
    assert report_path.is_file(), result.output
    sarif = json.loads(report_path.read_text(encoding="utf-8"))
    run = sarif["runs"][0]

    # Stage 1B provenance: contract_sha256 on run.properties + an invocations
    # block. SARIF 2.1.0 spells it ``run.invocations`` (an array), not the
    # singular ``invocation`` (#7).
    assert "contract_sha256" in run["properties"]
    assert run["properties"]["environment"] == "staging"
    assert run["properties"]["authorization_ref"] == "TICKET-42"
    assert "invocations" in run
    assert isinstance(run["invocations"], list)
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is True
    inv_props = invocation["properties"]
    assert "budgets_granted" in inv_props
    assert "budgets_consumed" in inv_props

    # An audit.jsonl provenance trail was written under the scan dir.
    scans_dir = tmp_path / ".agentguardian" / "scans"
    audit_files = list(scans_dir.glob("*/audit.jsonl"))
    assert audit_files, f"no audit.jsonl under {scans_dir}"
    audit = json.loads(audit_files[0].read_text(encoding="utf-8").strip())
    assert audit["contract_sha256"] == run["properties"]["contract_sha256"]
    assert audit["authorization_ref"] == "TICKET-42"
    assert audit["environment"] == "staging"
    assert audit["target_name"] == "contract-scan-demo"
    assert audit["budgets_granted"]["max_tokens"] == 50000
    assert audit["budgets_granted"]["parallel_workers"] == 4

    # The persisted scan.json carries the audit too.
    scan_json = audit_files[0].parent / "scan.json"
    assert scan_json.is_file()
    scan_payload = json.loads(scan_json.read_text(encoding="utf-8"))
    assert scan_payload["audit"]["contract_sha256"] == run["properties"]["contract_sha256"]


def test_scan_contract_mutually_exclusive_with_target(runner: CliRunner, tmp_path: Path) -> None:
    contract_path = tmp_path / "agentguardian.yaml"
    contract_path.write_text(_CONTRACT, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "some.dotted:path",
            "--contract",
            str(contract_path),
            "--model",
            "stub",
            "--no-tui",
        ],
    )

    assert result.exit_code == 2, result.output
    assert "mutually exclusive" in result.output
