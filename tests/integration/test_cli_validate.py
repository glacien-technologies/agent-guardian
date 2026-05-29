"""Integration tests for ``agent-guardian validate`` + ``init`` (Stage 1B).

Drive the CLI through :class:`typer.testing.CliRunner` with a respx-mocked HTTP
target and contract YAML in an isolated cwd. Covers the happy-path all-stages
green run, the prod-without-authorization refusal (exit 2), an unreachable
target (exit 3), ``--json`` output, the ``init --yes`` scaffold + pre-flight,
and the ``contract schema`` / ``contract migrate`` sub-app.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from agent_guardian.cli import (
    EXIT_CONFIG,
    EXIT_OK,
    EXIT_TARGET_UNREACHABLE,
    app,
)

URL = "https://api.example.com/v1/chat"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)


_MINIMAL = """
version: 1
target:
  name: demo-stateless
  environment: staging
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
  session:
    mode: stateless
roe:
  data_egress:
    allow_external: true
  budgets:
    max_tokens: 1000
"""

_PROD_UNAUTHORIZED = """
version: 1
target:
  name: prod-gateway
  environment: prod
  transport:
    kind: http
    url: https://api.example.com/v1/chat
  response:
    output_path: $.output.text
"""


def _write_contract(tmp_path: Path, body: str, name: str = "agentguardian.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# validate -- happy path
# ---------------------------------------------------------------------------


@respx.mock
def test_validate_happy_path_all_green(runner: CliRunner, tmp_path: Path) -> None:
    respx.post(URL).mock(
        return_value=httpx.Response(200, json={"output": {"text": "Hi, I am demo."}})
    )
    path = _write_contract(tmp_path, _MINIMAL)

    result = runner.invoke(app, ["validate", str(path)])

    assert result.exit_code == EXIT_OK, result.output
    assert "resolve+lint" in result.output
    assert "roe-echo" in result.output
    assert "PASS" in result.output
    # The redacted contract view is printed.
    assert "contract (redacted)" in result.output


@respx.mock
def test_validate_json_output(runner: CliRunner, tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "hello"}}))
    path = _write_contract(tmp_path, _MINIMAL)

    result = runner.invoke(app, ["validate", str(path), "--json"])

    assert result.exit_code == EXIT_OK, result.output
    import json

    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["exit_code"] == 0
    assert payload["contract_sha256"]
    assert len(payload["stages"]) == 7


@respx.mock
def test_validate_default_path_discovery(runner: CliRunner, tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "hi"}}))
    # Written as ./agentguardian.yaml -- the Argument default.
    _write_contract(tmp_path, _MINIMAL)

    result = runner.invoke(app, ["validate"])

    assert result.exit_code == EXIT_OK, result.output


# ---------------------------------------------------------------------------
# validate -- prod without authorization (exit 2)
# ---------------------------------------------------------------------------


def test_validate_prod_without_authorization_exits_config(
    runner: CliRunner, tmp_path: Path
) -> None:
    path = _write_contract(tmp_path, _PROD_UNAUTHORIZED)

    result = runner.invoke(app, ["validate", str(path)])

    assert result.exit_code == EXIT_CONFIG, result.output
    assert "FAIL" in result.output


# ---------------------------------------------------------------------------
# validate -- unreachable target (exit 3)
# ---------------------------------------------------------------------------


@respx.mock
def test_validate_unreachable_target_exits_unreachable(runner: CliRunner, tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
    path = _write_contract(tmp_path, _MINIMAL)

    result = runner.invoke(app, ["validate", str(path)])

    assert result.exit_code == EXIT_TARGET_UNREACHABLE, result.output
    assert "authenticate/probe" in result.output


@respx.mock
def test_validate_single_stage_filter(runner: CliRunner, tmp_path: Path) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "hi"}}))
    path = _write_contract(tmp_path, _MINIMAL)

    result = runner.invoke(app, ["validate", str(path), "--stage", "roe-echo"])

    assert result.exit_code == EXIT_OK, result.output
    assert "roe-echo" in result.output
    # Only the single stage line should appear (resolve+lint is not echoed).
    assert "resolve+lint" not in result.output


# ---------------------------------------------------------------------------
# init -- non-interactive scaffold + pre-flight
# ---------------------------------------------------------------------------


@respx.mock
def test_init_yes_writes_valid_contract(runner: CliRunner, tmp_path: Path) -> None:
    # The wizard defaults point at api.example.com; mock it so the post-write
    # pre-flight round-trips.
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    out = tmp_path / "scaffold.yaml"

    result = runner.invoke(app, ["init", "--out", str(out), "--yes"])

    assert out.is_file(), result.output
    assert "contract written to" in result.output
    # The default scaffold has egress off, so the benign round-trip is refused
    # (no send) -- the round-trip stage then sees the refusal text. We assert the
    # contract was authored + loads, not the network outcome.
    from agent_guardian.contract import load_contract

    contract = load_contract(out)
    assert contract.target.transport.kind == "http"


# ---------------------------------------------------------------------------
# contract sub-app
# ---------------------------------------------------------------------------


def test_contract_schema_writes_json_schema(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "contract.schema.json"

    result = runner.invoke(app, ["contract", "schema", "--out", str(out)])

    assert result.exit_code == 0, result.output
    assert out.is_file()
    import json

    schema = json.loads(out.read_text(encoding="utf-8"))
    assert schema["$id"].endswith("contract/v1.json")
    assert "$schema" in schema


def test_contract_migrate_current_version_is_passthrough(runner: CliRunner, tmp_path: Path) -> None:
    path = _write_contract(tmp_path, _MINIMAL, name="c.yaml")

    result = runner.invoke(app, ["contract", "migrate", str(path)])

    assert result.exit_code == 0, result.output
    # version 1 is current -> printed back unchanged.
    assert "demo-stateless" in result.output


def test_contract_migrate_unmigratable_version_exits_config(
    runner: CliRunner, tmp_path: Path
) -> None:
    path = _write_contract(
        tmp_path,
        "version: 2\n"
        "target:\n"
        "  name: future\n"
        "  environment: staging\n"
        "  transport:\n"
        "    kind: http\n"
        "    url: https://api.example.com/v1/chat\n"
        "  response:\n"
        "    output_path: $.output.text\n",
        name="v2.yaml",
    )

    result = runner.invoke(app, ["contract", "migrate", str(path), "--write"])

    assert result.exit_code == EXIT_CONFIG, result.output
    assert "migration failed" in result.output
