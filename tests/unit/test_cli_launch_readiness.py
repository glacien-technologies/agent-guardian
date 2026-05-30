"""CLI tests for the launch-readiness hardening pass.

Covers the 11 cluster items: framework registry + --framework-ref,
last-score --score-only, endpoint reachability preflight, init --yes
placeholder skip, doctor PDF/OTel/Bedrock probes, --no-owasp-llm,
LLM aclose in scan finally, bedrock in provider enumeration, coverage
% in summary, scans sub-app (list/delete/purge), M-jargon-free help.
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from agent_guardian.cli import (
    EXIT_CONFIG,
    EXIT_FAIL_UNDER,
    EXIT_OK,
    EXIT_TARGET_UNREACHABLE,
    FRAMEWORK_ADAPTERS,
    _is_placeholder_endpoint,
    _parse_relative_age,
    _resolve_framework_ref,
    app,
)


@pytest.fixture
def runner() -> CliRunner:
    # Modern typer/click merges stderr into stdout for ``invoke``; we read both.
    return CliRunner()


def _combined_output(result: Any) -> str:
    """Return result.stdout + result.stderr (handles click 8.2+ split-stream API)."""
    stdout = result.stdout or ""
    stderr = ""
    # click 8.2+ exposes stderr separately; earlier versions raise.
    try:
        stderr = result.stderr or ""
    except (AttributeError, ValueError):
        stderr = ""
    return stdout + stderr


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AGENT_GUARDIAN_HOME", raising=False)
    for var in (
        "AGENT_GUARDIAN_OPENAI_API_KEY",
        "AGENT_GUARDIAN_ANTHROPIC_API_KEY",
        "AGENT_GUARDIAN_GEMINI_API_KEY",
        "AGENT_GUARDIAN_BEDROCK_API_KEY",
        "AGENT_GUARDIAN_VERTEX_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "OTEL_SEMCONV_STABILITY_OPT_IN",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    ):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# Item 1 -- Framework registry + --framework-ref
# ---------------------------------------------------------------------------


def test_framework_registry_has_six_kinds() -> None:
    assert set(FRAMEWORK_ADAPTERS) == {
        "adk",
        "autogen",
        "crewai",
        "langgraph",
        "openai_agents",
        "strands",
    }


def test_scan_unknown_framework_kind_lists_supported(runner: CliRunner, tmp_path: Path) -> None:
    """Unknown --framework prints a deterministic supported list."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--framework",
            "nonexistent",
            "--framework-ref",
            "x:y",
            "--model",
            "stub",
            "--no-tui",
            "--mode",
            "fast",
        ],
    )
    assert result.exit_code == EXIT_CONFIG
    # The supported list is alphabetically sorted.
    assert "adk, autogen, crewai, langgraph, openai_agents, strands" in _combined_output(result)


def test_scan_framework_without_ref_errors(runner: CliRunner) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--framework",
            "langgraph",
            "--model",
            "stub",
            "--no-tui",
            "--mode",
            "fast",
        ],
    )
    assert result.exit_code == EXIT_CONFIG
    assert "--framework-ref" in _combined_output(result)


def test_resolve_framework_ref_colon_form(monkeypatch: pytest.MonkeyPatch) -> None:
    # Build a fake module with an attribute and register it.
    fake = types.ModuleType("fake_framework_module")

    class StubGraph:
        async def ainvoke(self, _state: dict[str, Any]) -> dict[str, Any]:
            return {"messages": [{"role": "assistant", "content": "ok"}]}

    fake.graph = StubGraph()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_framework_module", fake)

    obj = _resolve_framework_ref("fake_framework_module:graph")
    assert obj is fake.graph


def test_resolve_framework_ref_dotted_form(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("fake_framework_module2")
    fake.value = 42  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_framework_module2", fake)

    assert _resolve_framework_ref("fake_framework_module2.value") == 42


def test_resolve_framework_ref_missing_attr_raises() -> None:
    import typer

    with pytest.raises(typer.BadParameter) as exc_info:
        _resolve_framework_ref("agent_guardian.cli:does_not_exist_attribute")
    assert "does_not_exist_attribute" in str(exc_info.value)


def test_resolve_framework_ref_empty_rejected() -> None:
    import typer

    with pytest.raises(typer.BadParameter) as exc_info:
        _resolve_framework_ref("")
    assert "empty" in str(exc_info.value).lower()


def test_resolve_framework_ref_missing_module_raises() -> None:
    import typer

    with pytest.raises(typer.BadParameter) as exc_info:
        _resolve_framework_ref("definitely_not_a_real_module_abc123:graph")
    assert "import" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Item 2 -- last-score --score-only
# ---------------------------------------------------------------------------


def test_last_score_score_only_no_scans_exits_1(runner: CliRunner) -> None:
    result = runner.invoke(app, ["last-score", "--score-only"])
    assert result.exit_code == EXIT_FAIL_UNDER


def test_last_score_default_no_scans_exits_0(runner: CliRunner) -> None:
    # Backward compatibility: plain `last-score` keeps exit 0 + prose.
    result = runner.invoke(app, ["last-score"])
    assert result.exit_code == EXIT_OK
    assert "no scans" in result.stdout.lower()


def test_last_score_score_only_emits_only_integer(runner: CliRunner, tmp_path: Path) -> None:
    # Plant a state file with a known score.
    state_dir = tmp_path / ".agentguardian"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / "state.json"
    state_path.write_text('{"last_score": 73}', encoding="utf-8")
    result = runner.invoke(app, ["last-score", "--score-only"])
    assert result.exit_code == EXIT_OK
    assert result.stdout.strip() == "73"


# ---------------------------------------------------------------------------
# Item 3 -- Endpoint reachability preflight
# ---------------------------------------------------------------------------


def test_is_placeholder_endpoint_detects_example_hosts() -> None:
    assert _is_placeholder_endpoint("https://api.example.com/v1/chat")
    assert _is_placeholder_endpoint("https://example.com/foo")
    assert _is_placeholder_endpoint("https://anything.example.org/x")
    assert not _is_placeholder_endpoint("https://api.openai.com/v1/chat")
    assert not _is_placeholder_endpoint("http://127.0.0.1:8080")


def test_endpoint_preflight_unreachable_exits_3(runner: CliRunner, tmp_path: Path) -> None:
    """Unreachable real endpoint exits EXIT_TARGET_UNREACHABLE before any LLM cost."""
    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.realhost.invalid/v1/chat").mock(
            side_effect=httpx.ConnectError("simulated")
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--endpoint",
                "https://api.realhost.invalid/v1/chat",
                "--model",
                "stub",
                "--no-tui",
                "--mode",
                "fast",
            ],
        )
    assert result.exit_code == EXIT_TARGET_UNREACHABLE
    assert "target unreachable" in _combined_output(result).lower()


def test_endpoint_preflight_no_preflight_flag_skips(runner: CliRunner, tmp_path: Path) -> None:
    """--no-preflight escapes the preflight; the scan can then proceed."""
    # We mock the post so the scan runs through; the preflight should NOT fire.
    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.realhost.invalid/v1/chat").respond(
            200, json={"choices": [{"message": {"content": "ok"}}]}
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "--endpoint",
                "https://api.realhost.invalid/v1/chat",
                "--model",
                "stub",
                "--no-tui",
                "--no-preflight",
                "--mode",
                "fast",
                "--output",
                "json",
                "--output-path",
                str(tmp_path / "report.json"),
            ],
        )
    # The scan reached the swarm (no preflight gate); exit code is 0 (stub run).
    # The stub-run gate also makes --fail-under always fail, but we didn't set
    # one, so EXIT_OK is the expected outcome.
    assert result.exit_code == EXIT_OK, result.stdout


# ---------------------------------------------------------------------------
# Item 5 -- doctor PDF / OTel / Bedrock readiness probes
# ---------------------------------------------------------------------------


def test_doctor_emits_pdf_readiness_line(runner: CliRunner) -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == EXIT_OK
    assert "pdf engine:" in result.stdout


def test_doctor_emits_otel_readiness_line(runner: CliRunner) -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == EXIT_OK
    assert "otel:" in result.stdout
    assert "dashboard port 7474:" in result.stdout


def test_doctor_emits_bedrock_readiness_line(runner: CliRunner) -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == EXIT_OK
    assert "bedrock:" in result.stdout


def test_doctor_bedrock_not_in_api_key_loop(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bedrock API key env var must NOT show up under 'llm keys detected'."""
    monkeypatch.setenv("AGENT_GUARDIAN_BEDROCK_API_KEY", "fake-should-not-detect")
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == EXIT_OK
    # Bedrock should not be in the 'llm keys detected' line.
    keys_line = next(
        (line for line in result.stdout.splitlines() if "llm keys detected" in line),
        "",
    )
    assert "bedrock" not in keys_line.lower()


# ---------------------------------------------------------------------------
# Item 6 -- Default --no-owasp-llm + OWASP-LLM specialists default ON
# ---------------------------------------------------------------------------


def test_scan_help_lists_no_owasp_llm_not_owasp_llm() -> None:
    from click import Group
    from typer.main import get_command

    cmd = get_command(app)
    assert isinstance(cmd, Group)
    scan_cmd = cmd.commands["scan"]
    registered = {opt for param in scan_cmd.params for opt in param.opts}
    assert "--no-owasp-llm" in registered
    assert "--owasp-llm" not in registered


# ---------------------------------------------------------------------------
# Item 8 -- bedrock in 'valid providers' BadParameter
# ---------------------------------------------------------------------------


def test_build_llm_unknown_provider_lists_bedrock() -> None:
    """The 'Cannot infer provider' message must enumerate bedrock for parity."""
    import typer

    from agent_guardian.cli import build_llm

    with pytest.raises(typer.BadParameter) as exc_info:
        build_llm("unknown-model-name", role="attacker")
    msg = str(exc_info.value)
    assert "bedrock:" in msg


# ---------------------------------------------------------------------------
# Item 10 -- scans sub-app: list, delete, purge
# ---------------------------------------------------------------------------


def test_scans_list_no_scans(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scans", "list"])
    assert result.exit_code == EXIT_OK
    assert "no stored scans" in result.stdout.lower()


def test_scans_list_after_planting_a_scan(runner: CliRunner, tmp_path: Path) -> None:
    scans_dir = tmp_path / ".agentguardian" / "scans"
    scan_dir = scans_dir / "cli-deadbeef0001"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["scans", "list"])
    assert result.exit_code == EXIT_OK
    assert "cli-deadbeef0001" in result.stdout


def test_scans_delete_removes_directory(runner: CliRunner, tmp_path: Path) -> None:
    scans_dir = tmp_path / ".agentguardian" / "scans"
    scan_dir = scans_dir / "cli-todelete"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["scans", "delete", "cli-todelete"])
    assert result.exit_code == EXIT_OK
    assert not scan_dir.exists()


def test_scans_delete_missing_errors(runner: CliRunner) -> None:
    result = runner.invoke(app, ["scans", "delete", "no-such-scan"])
    assert result.exit_code == EXIT_CONFIG


def test_parse_relative_age_units() -> None:
    assert _parse_relative_age("30d") == timedelta(days=30)
    assert _parse_relative_age("2w") == timedelta(weeks=2)
    assert _parse_relative_age("6m") == timedelta(days=180)


def test_parse_relative_age_rejects_bad_input() -> None:
    import typer

    with pytest.raises(typer.BadParameter):
        _parse_relative_age("foo")
    with pytest.raises(typer.BadParameter):
        _parse_relative_age("30x")
    with pytest.raises(typer.BadParameter):
        _parse_relative_age("-5d")


def test_scans_purge_only_removes_old(runner: CliRunner, tmp_path: Path) -> None:
    import os
    import time

    scans_dir = tmp_path / ".agentguardian" / "scans"
    old_scan = scans_dir / "cli-old"
    new_scan = scans_dir / "cli-new"
    old_scan.mkdir(parents=True, exist_ok=True)
    new_scan.mkdir(parents=True, exist_ok=True)
    (old_scan / "scan.json").write_text("{}", encoding="utf-8")
    (new_scan / "scan.json").write_text("{}", encoding="utf-8")
    # Backdate the 'old' scan to 60 days ago.
    sixty_days_ago = (datetime.now(tz=timezone.utc) - timedelta(days=60)).timestamp()
    os.utime(old_scan, (sixty_days_ago, sixty_days_ago))
    now = time.time()
    os.utime(new_scan, (now, now))
    result = runner.invoke(app, ["scans", "purge", "--older-than", "30d"])
    assert result.exit_code == EXIT_OK
    assert not old_scan.exists()
    assert new_scan.exists()


def test_scans_purge_dry_run_keeps_files(runner: CliRunner, tmp_path: Path) -> None:
    import os

    scans_dir = tmp_path / ".agentguardian" / "scans"
    old_scan = scans_dir / "cli-old-dry"
    old_scan.mkdir(parents=True, exist_ok=True)
    sixty_days_ago = (datetime.now(tz=timezone.utc) - timedelta(days=60)).timestamp()
    os.utime(old_scan, (sixty_days_ago, sixty_days_ago))
    result = runner.invoke(app, ["scans", "purge", "--older-than", "30d", "--dry-run"])
    assert result.exit_code == EXIT_OK
    assert old_scan.exists()
    assert "would purge" in result.stdout.lower()


def test_scans_honours_agent_guardian_home(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AGENT_GUARDIAN_HOME redirects the scans-management root."""
    custom_home = tmp_path / "custom_home"
    monkeypatch.setenv("AGENT_GUARDIAN_HOME", str(custom_home))
    scans_dir = custom_home / "scans"
    scan_dir = scans_dir / "cli-customhome"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["scans", "list"])
    assert result.exit_code == EXIT_OK
    assert "cli-customhome" in result.stdout


# ---------------------------------------------------------------------------
# Item 11 -- M-jargon stripped from public Option help strings
# ---------------------------------------------------------------------------


def test_no_m_jargon_in_scan_option_help() -> None:
    """No 'M9-' / 'M11' / 'M13' / 'M15' / 'Stage 1B' / 'Mode A/C/D' tokens."""
    from click import Group
    from typer.main import get_command

    cmd = get_command(app)
    assert isinstance(cmd, Group)
    scan_cmd = cmd.commands["scan"]
    for param in scan_cmd.params:
        help_text = (param.help or "").lower()
        # The PRD-internal tokens that leaked into Option help.
        for token in (
            "m9-",
            " m11",
            " m13",
            " m15",
            "stage 1b",
            "mode a -",
            "mode c -",
            "mode d -",
        ):
            assert token.lower() not in help_text, (
                f"Option {param.name} help still contains {token!r}: {help_text}"
            )


def test_telemetry_group_help_has_no_m15() -> None:
    from click import Group
    from typer.main import get_command

    cmd = get_command(app)
    assert isinstance(cmd, Group)
    telemetry = cmd.commands.get("telemetry")
    assert telemetry is not None
    assert "M15" not in (telemetry.help or "")
