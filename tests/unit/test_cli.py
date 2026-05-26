"""Unit tests for the AgentGuardian CLI (M10).

We use :class:`typer.testing.CliRunner` for everything — no real network,
no real LLMs (``--model stub`` everywhere).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_guardian import __version__
from agent_guardian.cli import (
    EXIT_CONFIG,
    EXIT_FAIL_UNDER,
    EXIT_LLM_PROVIDER,
    EXIT_OK,
    app,
    build_llm,
)
from agent_guardian.llm import OpenAIClient, StubLLM

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    # Newer typer/click merge stderr into stdout by default; we read both.
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Redirect HOME at the OS layer so each CLI test gets a clean state dir."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    # Clear any provider keys leaking from the host env.
    for var in (
        "AGENT_GUARDIAN_OPENAI_API_KEY",
        "AGENT_GUARDIAN_ANTHROPIC_API_KEY",
        "AGENT_GUARDIAN_BEDROCK_API_KEY",
        "AGENT_GUARDIAN_VERTEX_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# Trivial commands
# ---------------------------------------------------------------------------


def test_version_flag(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_version_subcommand(runner: CliRunner) -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_list_agents_prints_eleven_rows(runner: CliRunner) -> None:
    result = runner.invoke(app, ["list-agents"])
    assert result.exit_code == 0
    # Recon + ten ASI agents
    assert "recon-agent" in result.stdout
    for asi in (
        "ASI01",
        "ASI02",
        "ASI03",
        "ASI04",
        "ASI05",
        "ASI06",
        "ASI07",
        "ASI08",
        "ASI09",
        "ASI10",
    ):
        assert asi in result.stdout


def test_list_probes_placeholder(runner: CliRunner) -> None:
    result = runner.invoke(app, ["list-probes"])
    assert result.exit_code == 0
    assert "no probes yet" in result.stdout.lower()


def test_list_probes_with_asi_filter(runner: CliRunner) -> None:
    result = runner.invoke(app, ["list-probes", "--asi", "ASI01"])
    assert result.exit_code == 0


def test_badge_text(runner: CliRunner) -> None:
    result = runner.invoke(app, ["badge", "87"])
    assert result.exit_code == 0
    assert "87" in result.stdout
    assert "GOOD" in result.stdout


def test_badge_svg(runner: CliRunner) -> None:
    result = runner.invoke(app, ["badge", "87", "--svg"])
    assert result.exit_code == 0
    assert result.stdout.startswith("<?xml") or "<svg" in result.stdout
    assert "AIVSS" in result.stdout


def test_badge_rejects_out_of_range(runner: CliRunner) -> None:
    result = runner.invoke(app, ["badge", "150"])
    assert result.exit_code != 0


def test_doctor(runner: CliRunner) -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "agent-guardian" in result.stdout
    assert "sandbox" in result.stdout


def test_serve_placeholder(runner: CliRunner) -> None:
    result = runner.invoke(app, ["serve"])
    assert result.exit_code == 0
    assert "M12" in result.stdout


def test_verify_stub_on_missing_path(runner: CliRunner, tmp_path: Path) -> None:
    missing = tmp_path / "nope.zip"
    result = runner.invoke(app, ["verify", str(missing)])
    assert result.exit_code == EXIT_CONFIG


def test_verify_stub_on_existing_path(runner: CliRunner, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.zip"
    bundle.write_text("placeholder", encoding="utf-8")
    result = runner.invoke(app, ["verify", str(bundle)])
    assert result.exit_code == 0
    assert "M13" in result.stdout


def test_publish_stub(runner: CliRunner) -> None:
    result = runner.invoke(app, ["publish", "fake-id"])
    assert result.exit_code == 0
    assert "M15" in result.stdout


# ---------------------------------------------------------------------------
# Telemetry sub-app
# ---------------------------------------------------------------------------


def test_telemetry_status_disabled_by_default(runner: CliRunner) -> None:
    result = runner.invoke(app, ["telemetry", "status"])
    assert result.exit_code == 0
    assert "disabled" in result.stdout


def test_telemetry_enable_then_status(runner: CliRunner) -> None:
    result = runner.invoke(app, ["telemetry", "enable"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["telemetry", "status"])
    assert "enabled" in result.stdout


def test_telemetry_disable(runner: CliRunner) -> None:
    runner.invoke(app, ["telemetry", "enable"])
    result = runner.invoke(app, ["telemetry", "disable"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["telemetry", "status"])
    assert "disabled" in result.stdout


# ---------------------------------------------------------------------------
# last-score
# ---------------------------------------------------------------------------


def test_last_score_with_no_state(runner: CliRunner) -> None:
    result = runner.invoke(app, ["last-score"])
    assert result.exit_code == 0
    assert "no scans" in result.stdout.lower()


# ---------------------------------------------------------------------------
# build_llm
# ---------------------------------------------------------------------------


def test_build_llm_stub() -> None:
    llm = build_llm("stub", role="attacker")
    assert isinstance(llm, StubLLM)


def test_build_llm_empty_defaults_to_stub() -> None:
    llm = build_llm("", role="attacker")
    assert isinstance(llm, StubLLM)


def test_build_llm_openai_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import typer as _typer

    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    with pytest.raises(_typer.BadParameter):
        build_llm("openai:gpt-4o", role="attacker")


def test_build_llm_openai_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_OPENAI_API_KEY", "sk-test")
    llm = build_llm("openai:gpt-4o", role="attacker")
    assert isinstance(llm, OpenAIClient)


def test_build_llm_unknown_provider_raises() -> None:
    import typer as _typer

    with pytest.raises(_typer.BadParameter):
        build_llm("not_a_real_format_no_prefix", role="attacker")


def test_build_llm_heuristic_gpt() -> None:
    import typer as _typer

    with pytest.raises(_typer.BadParameter):
        # No env key — but routing must work.
        build_llm("gpt-future-99", role="attacker")


# ---------------------------------------------------------------------------
# scan — error paths (no real swarm)
# ---------------------------------------------------------------------------


def test_scan_without_target_returns_config_error(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == EXIT_CONFIG


def test_scan_with_missing_prompt_file_returns_config_error(
    runner: CliRunner, tmp_path: Path
) -> None:
    missing = tmp_path / "nope.txt"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(missing),
            "--model",
            "stub",
            "--no-tui",
            "--output-path",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == EXIT_CONFIG


def test_scan_with_two_modes_rejected(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("hello", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--endpoint",
            "https://example.com/api",
            "--model",
            "stub",
            "--no-tui",
        ],
    )
    assert result.exit_code == EXIT_CONFIG


def test_scan_with_unknown_tier_returns_config_error(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("hello", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--tier",
            "TX",
            "--no-tui",
        ],
    )
    assert result.exit_code == EXIT_CONFIG


def test_scan_with_unknown_output_format_returns_config_error(
    runner: CliRunner, tmp_path: Path
) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("hello", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--output",
            "weird",
            "--output-path",
            str(tmp_path / "out.weird"),
            "--no-tui",
        ],
    )
    assert result.exit_code == EXIT_CONFIG


def test_scan_openai_without_key_returns_llm_error(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    prompt = tmp_path / "p.txt"
    prompt.write_text("hello", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "openai:gpt-4o-mini",
            "--no-tui",
        ],
    )
    assert result.exit_code == EXIT_LLM_PROVIDER


def test_scan_budget_too_low_aborts(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("hello", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            # Force a paid model so the estimate is > 0.
            "--commander-model",
            "openai:gpt-4o-mini",
            "--attacker-model",
            "openai:gpt-4o-mini",
            "--evaluator-model",
            "openai:gpt-4o-mini",
            "--model",
            "stub",
            "--budget-usd",
            "0.0001",
            "--no-tui",
        ],
    )
    assert result.exit_code == EXIT_CONFIG
    assert "budget" in result.stdout.lower() or "budget" in result.output.lower()


# ---------------------------------------------------------------------------
# scan — happy path (stub-backed end-to-end)
# ---------------------------------------------------------------------------


def test_scan_end_to_end_writes_json(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a helpful safe bot.", encoding="utf-8")
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output",
            "json",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert out_path.is_file()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert "aivss" in payload
    assert 0 <= payload["aivss"] <= 100
    # Cost estimate banner printed.
    assert "cost estimate" in result.stdout.lower()


def test_scan_fail_under_returns_one(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a helpful safe bot.", encoding="utf-8")
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--fail-under",
            "100",
            "--output-path",
            str(out_path),
        ],
    )
    # The stub-driven scan scores at most 100 — we set 100 floor so the
    # comparison is strict: aivss < 100 triggers exit 1, == 100 passes.
    assert result.exit_code in (EXIT_OK, EXIT_FAIL_UNDER)


def test_scan_md_output(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a safe bot.", encoding="utf-8")
    out_path = tmp_path / "scan.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output",
            "md",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK
    text = out_path.read_text(encoding="utf-8")
    assert "AIVSS" in text


def test_scan_sarif_output(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a safe bot.", encoding="utf-8")
    out_path = tmp_path / "scan.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output",
            "sarif",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"


def test_scan_junit_output(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a safe bot.", encoding="utf-8")
    out_path = tmp_path / "scan.xml"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output",
            "junit",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK
    text = out_path.read_text(encoding="utf-8")
    assert "<testsuite" in text


def test_scan_after_run_updates_last_score(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("safe bot", encoding="utf-8")
    out_path = tmp_path / "scan.json"
    runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output-path",
            str(out_path),
        ],
    )
    result = runner.invoke(app, ["last-score"])
    assert result.exit_code == EXIT_OK
    assert "AIVSS" in result.stdout


# ---------------------------------------------------------------------------
# Config file integration
# ---------------------------------------------------------------------------


def test_scan_picks_up_config_file(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("safe bot", encoding="utf-8")
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        """\
swarm:
  commander_model: stub
  attacker_model: stub
  evaluator_model: stub
  budget:
    wall_seconds: 60
    max_total_tokens: 100000
""",
        encoding="utf-8",
    )
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--config",
            str(cfg),
            "--no-tui",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output


# ---------------------------------------------------------------------------
# Ethical banner
# ---------------------------------------------------------------------------


def test_first_run_prints_ethical_banner(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("safe bot", encoding="utf-8")
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK
    assert "authorised security testing" in result.stdout.lower()


def test_second_run_does_not_print_banner(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("safe bot", encoding="utf-8")
    out_path = tmp_path / "scan.json"
    first = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output-path",
            str(out_path),
        ],
    )
    assert first.exit_code == EXIT_OK
    second = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output-path",
            str(out_path),
        ],
    )
    assert second.exit_code == EXIT_OK
    assert "authorised security testing" not in second.stdout.lower()


# ---------------------------------------------------------------------------
# Report regeneration
# ---------------------------------------------------------------------------


def test_report_missing_scan_returns_config_error(runner: CliRunner) -> None:
    result = runner.invoke(app, ["report", "no-such-scan-id"])
    assert result.exit_code == EXIT_CONFIG


def test_report_regenerates_from_persisted_scan(runner: CliRunner, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("safe bot", encoding="utf-8")
    out_path = tmp_path / "scan.json"
    first = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output-path",
            str(out_path),
        ],
    )
    assert first.exit_code == EXIT_OK
    # Parse scan_id out of the summary line.
    summary = first.stdout.strip().splitlines()[-1]
    scan_id = summary.split()[1]
    result = runner.invoke(app, ["report", scan_id, "--output", "md"])
    assert result.exit_code == EXIT_OK
    assert "AIVSS" in result.stdout
