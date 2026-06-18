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
    EXIT_OK,
    app,
    build_llm,
)
from agent_guardian.llm import GeminiClient, OpenAIClient, StubLLM

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_scan_id_from_summary(stdout: str) -> str:
    """Pluck the scan_id from the ``scan <id> done: ...`` summary line.

    Before QA-049 every CLI test parsed the *last* line of stdout to
    grab the scan_id, because the summary line was always the last
    line emitted. QA-049 added a prominent dashboard-URL banner after
    the summary (a Rich rule + URL line), so the last-line heuristic
    breaks. This helper finds the summary line by prefix so the tests
    are robust against later additions to the scan-end footer.
    """
    for line in stdout.strip().splitlines():
        if line.startswith("scan ") and " done:" in line:
            return line.split()[1]
    raise AssertionError(
        f"could not find a `scan <id> done: ...` summary line in stdout:\n{stdout}"
    )


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
    # Clear any provider keys leaking from the host env — both the
    # namespaced AGENT_GUARDIAN_* vars and the standard fallbacks the
    # post-M15 env_api_key() resolves via.
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


def test_list_agents_and_list_probes_removed(runner: CliRunner) -> None:
    # Removed (closes #106): the roster now lives in the per-scan report.
    assert runner.invoke(app, ["list-agents"]).exit_code != 0
    assert runner.invoke(app, ["list-probes"]).exit_code != 0


def test_report_carries_agent_roster(runner: CliRunner, tmp_path: Path) -> None:
    # #106 closure: the authoritative roster of agents that ran is in the report
    # artifact (coverage.agents), not a drift-prone static CLI command.
    scan_id = _stub_scan_id(runner, tmp_path)
    result = runner.invoke(app, ["report", scan_id, "--output", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    coverage = payload["coverage"]
    assert "agents" in coverage
    assert "skipped_agents" in coverage
    # The roster of agents that ran is enumerated in the artifact (a multi-agent
    # swarm, not the static "eleven" the removed list-agents advertised).
    assert len(coverage["agents"]) >= 5


def _stub_scan_id(runner: CliRunner, tmp_path: Path) -> str:
    """Run a fast stub scan and return its scan id (HOME is pinned to tmp_path)."""
    prompt = tmp_path / "p.txt"
    prompt.write_text("safe bot", encoding="utf-8")
    res = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--output-path",
            str(tmp_path / "scan.json"),
        ],
    )
    assert res.exit_code == EXIT_OK, res.stdout
    return _extract_scan_id_from_summary(res.stdout)


def test_report_badge_text(runner: CliRunner, tmp_path: Path) -> None:
    # `badge` was folded into `report --output badge`.
    scan_id = _stub_scan_id(runner, tmp_path)
    result = runner.invoke(app, ["report", scan_id, "--output", "badge"])
    assert result.exit_code == 0
    assert "AIVSS" in result.stdout


def test_report_badge_svg(runner: CliRunner, tmp_path: Path) -> None:
    scan_id = _stub_scan_id(runner, tmp_path)
    result = runner.invoke(app, ["report", scan_id, "--output", "badge-svg"])
    assert result.exit_code == 0
    assert "<svg" in result.stdout


def test_badge_command_removed(runner: CliRunner) -> None:
    # The standalone `badge` command no longer exists.
    result = runner.invoke(app, ["badge", "87"])
    assert result.exit_code != 0


def test_gate_fails_on_stub_scan(runner: CliRunner, tmp_path: Path) -> None:
    # A stub scan is non-authoritative and never passes a gate -- that guard is
    # the contract: `gate` loads the stored scan and applies evaluate_gate.
    scan_id = _stub_scan_id(runner, tmp_path)
    result = runner.invoke(app, ["gate", scan_id, "--fail-under", "1"])
    assert result.exit_code == EXIT_FAIL_UNDER
    assert "gate FAIL" in (result.stdout + result.stderr)


def test_gate_unknown_scan_errors(runner: CliRunner) -> None:
    result = runner.invoke(app, ["gate", "no-such-scan"])
    assert result.exit_code == EXIT_CONFIG


def test_config_show_defaults(runner: CliRunner) -> None:
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "built-in defaults" in result.stdout
    assert "swarm:" in result.stdout


def test_config_init_writes_and_refuses_overwrite(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "cfg.yaml"
    first = runner.invoke(app, ["config", "init", "--out", str(out)])
    assert first.exit_code == 0
    assert out.is_file()
    second = runner.invoke(app, ["config", "init", "--out", str(out)])
    assert second.exit_code == EXIT_CONFIG
    forced = runner.invoke(app, ["config", "init", "--out", str(out), "--force"])
    assert forced.exit_code == 0


def test_doctor(runner: CliRunner) -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "agent-guardian" in result.stdout
    assert "sandbox" in result.stdout


def test_serve_invokes_uvicorn_with_factory(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``agent-guardian serve`` must hand a constructed FastAPI app to uvicorn.

    Post a8c8ee6, the non-reload path constructs the app eagerly so the CLI
    can stamp ``app.state.dashboard_token`` BEFORE uvicorn starts accepting
    connections — otherwise the dashboard token would not be available on the
    very first request. This means ``factory=True`` is intentionally NOT
    passed in the non-reload path. The reload path still uses an import
    string + factory (see ``test_serve_reload_passes_import_string``).
    """
    captured: dict[str, object] = {}

    def fake_run(target: object, **kwargs: object) -> None:
        captured["target"] = target
        captured["kwargs"] = kwargs

    import uvicorn
    from fastapi import FastAPI

    monkeypatch.setattr(uvicorn, "run", fake_run)
    result = runner.invoke(app, ["serve", "--host", "127.0.0.1", "--port", "9999"])
    assert result.exit_code == 0
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 9999
    # Non-reload path: target is a constructed FastAPI app with a stamped
    # dashboard_token, NOT an import string + factory=True.
    assert "factory" not in kwargs
    assert isinstance(captured["target"], FastAPI)


def test_serve_reload_passes_import_string(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--reload`` requires uvicorn's import-string form, not a callable."""
    captured: dict[str, object] = {}

    def fake_run(target: object, **kwargs: object) -> None:
        captured["target"] = target
        captured["kwargs"] = kwargs

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    result = runner.invoke(app, ["serve", "--reload"])
    assert result.exit_code == 0
    # Reload path must hand uvicorn the import-string form, not a callable.
    assert captured["target"] == "agent_guardian.server.app:create_app"
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["reload"] is True
    assert kwargs["factory"] is True


def test_verify_missing_path(runner: CliRunner, tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    result = runner.invoke(app, ["verify", str(missing)])
    assert result.exit_code == EXIT_CONFIG


def test_verify_rejects_non_json_suffix(runner: CliRunner, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.zip"
    bundle.write_text("placeholder", encoding="utf-8")
    result = runner.invoke(app, ["verify", str(bundle)])
    assert result.exit_code == EXIT_CONFIG


def test_verify_unanchored_refuses_green(runner: CliRunner, tmp_path: Path) -> None:
    """A freshly signed report with NO trust anchor is integrity-OK but the
    command must refuse a green result (fail closed) and exit non-zero (#6)."""
    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    path = tmp_path / "report.json"
    write_json(make_scan(), path)
    result = runner.invoke(app, ["verify", str(path)])
    assert result.exit_code != 0
    out = result.stdout + (result.stderr or "")
    assert "UNANCHORED" in out
    assert "provenance" in out.lower()


def test_verify_pinned_pubkey_anchors_genuine_report_without_hmac_secret(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Pinning the report's Ed25519 pubkey is a sufficient trust anchor (#6).

    A genuine report signed only with the public default HMAC secret still
    verifies GREEN when its Ed25519 key is pinned and valid: the HMAC channel
    (worthless without a real secret, so it fails closed) must NOT veto a
    pinned-and-valid Ed25519. This is the common operator trust scenario —
    requiring a real HMAC secret too would make the default signing path
    impossible to verify."""
    import json as _json

    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    path = tmp_path / "report.json"
    write_json(make_scan(), path)  # signed with the public default HMAC secret
    payload = _json.loads(path.read_text(encoding="utf-8"))
    pubkey = payload["signatures"]["ed25519"]["public_key_b32"]
    result = runner.invoke(app, ["verify", str(path), "--pubkey", pubkey])
    # Ed25519 integrity holds + pin matches -> anchored & green; HMAC has no
    # operator-supplied secret to validate against, so the renderer surfaces
    # the channel as ``NO-SECRET`` rather than ``FAIL`` (QA-G17). The earlier
    # FAIL label landed first on the line and read as a tamper signal even on
    # a clean self-produced scan — the distinguishing label keeps the
    # pinned-pubkey trust path green without lying about the HMAC channel.
    assert result.exit_code == 0, (result.stdout, result.stderr)
    assert "PINNED" in result.stdout
    assert "Ed25519:      OK" in result.stdout
    assert "HMAC-SHA256:  NO-SECRET" in result.stdout


def test_verify_succeeds_with_real_hmac_secret(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Signing + verifying with a real (non-default) HMAC secret plus a pinned
    Ed25519 pubkey anchors trust and yields a green (exit 0) result."""
    import json as _json

    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    monkeypatch.setenv("AGENT_GUARDIAN_SIGNING_SECRET", "a-real-ci-secret")
    path = tmp_path / "report.json"
    write_json(make_scan(), path)  # signed with the real env secret
    payload = _json.loads(path.read_text(encoding="utf-8"))
    pubkey = payload["signatures"]["ed25519"]["public_key_b32"]
    result = runner.invoke(
        app, ["verify", str(path), "--secret", "a-real-ci-secret", "--pubkey", pubkey]
    )
    assert result.exit_code == 0, (result.stdout, result.stderr)
    assert "PINNED" in result.stdout


def test_verify_fails_on_tampered_report(runner: CliRunner, tmp_path: Path) -> None:
    import json as _json

    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    path = tmp_path / "report.json"
    write_json(make_scan(), path)
    data = _json.loads(path.read_text(encoding="utf-8"))
    data["aivss"] = 0
    path.write_text(_json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    result = runner.invoke(app, ["verify", str(path)])
    assert result.exit_code != 0
    assert "FAIL" in result.stdout


# ---------------------------------------------------------------------------
# Telemetry sub-app
# ---------------------------------------------------------------------------


def test_telemetry_status_disabled_by_default(runner: CliRunner) -> None:
    """Fresh install reports NOT_PROMPTED (the default consent state)."""
    result = runner.invoke(app, ["telemetry", "status"])
    assert result.exit_code == 0
    # New status output is "telemetry state: not_prompted" + hint line.
    assert "not_prompted" in result.stdout
    assert "opted in" in result.stdout.lower() or "not_prompted" in result.stdout


def test_telemetry_enable_then_status(runner: CliRunner) -> None:
    """`enable` (legacy alias of `extended`) upgrades to EXTENDED tier."""
    result = runner.invoke(app, ["telemetry", "enable"])
    assert result.exit_code == 0
    # The new wording reflects the tier upgrade, not "enabled".
    assert "extended" in result.stdout.lower()
    result = runner.invoke(app, ["telemetry", "status"])
    assert "extended" in result.stdout


def test_telemetry_disable(runner: CliRunner) -> None:
    """`disable` transitions OPTED_IN → OPTED_OUT and surfaces in status."""
    runner.invoke(app, ["telemetry", "enable"])
    result = runner.invoke(app, ["telemetry", "disable"])
    assert result.exit_code == 0
    assert "disabled" in result.stdout.lower()
    result = runner.invoke(app, ["telemetry", "status"])
    assert "opted_out" in result.stdout


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


def test_build_llm_routes_gemini_prefix_heuristic(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bare ``gemini-...`` spec routes to the AI Studio Gemini client."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    llm = build_llm("gemini-3.1-pro-preview", role="attacker")
    assert isinstance(llm, GeminiClient)
    assert llm.provider == "gemini"


def test_build_llm_explicit_gemini_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``gemini:<model>`` prefix routes to GeminiClient regardless of name."""
    monkeypatch.setenv("GEMINI_API_KEY", "test")
    llm = build_llm("gemini:gemini-3.5-flash", role="evaluator")
    assert isinstance(llm, GeminiClient)


def test_build_llm_gemini_accepts_google_api_key_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``GOOGLE_API_KEY`` is honoured as a fallback for ``gemini`` routing."""
    monkeypatch.setenv("GOOGLE_API_KEY", "google-key")
    llm = build_llm("gemini-3.1-pro-preview", role="attacker")
    assert isinstance(llm, GeminiClient)


def test_build_llm_gemini_missing_key_errors_with_all_three_options() -> None:
    """The missing-key error message must name every accepted env var so the
    operator can pick whichever one fits their setup."""
    import typer as _typer

    with pytest.raises(_typer.BadParameter, match="no API key found") as exc_info:
        build_llm("gemini-3.1-pro-preview", role="attacker")
    message = str(exc_info.value)
    assert "AGENT_GUARDIAN_GEMINI_API_KEY" in message
    assert "GEMINI_API_KEY" in message
    assert "GOOGLE_API_KEY" in message


def test_build_llm_openai_with_standard_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPENAI_API_KEY (standard env var) works alongside the namespaced one."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-standard")
    llm = build_llm("openai:gpt-4o", role="attacker")
    assert isinstance(llm, OpenAIClient)


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
    """Missing API key is a configuration problem (EXIT_CONFIG=2), not a provider
    fault (EXIT_LLM_PROVIDER=4). The QA-001 model-validation preflight detects
    the missing credential before any provider round-trip and exits via
    EXIT_CONFIG so operators get the right "set this env var" remediation
    rather than a "provider failed" red herring.
    """
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
    assert result.exit_code == EXIT_CONFIG


def test_scan_low_budget_does_not_abort_preflight(runner: CliRunner, tmp_path: Path) -> None:
    """A tiny --budget-usd no longer aborts before the scan runs.

    The mode-blind pre-flight estimate gate was removed; --budget-usd is now a
    *runtime* cap metered against actual spend. With the free stub model the cap
    is never reached, so the scan runs to completion (EXIT_OK) and prints the
    cap notice rather than a 'budget exceeded' abort.
    """
    prompt = tmp_path / "p.txt"
    prompt.write_text("hello", encoding="utf-8")
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--budget-usd",
            "0.0001",
            "--no-tui",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "cost estimate" not in result.output.lower()
    assert "budget cap" in result.output.lower()


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
    # Issue #261 — a stub-evaluator scan ships ``scoring_valid=False``, so
    # ``aivss`` in the rendered report is suppressed to ``None`` (the
    # in-memory Scan still carries the numeric for trend-tracking). A real
    # evaluator path returns an integer in [0,100].
    if payload.get("scoring_valid"):
        assert isinstance(payload["aivss"], int)
        assert 0 <= payload["aivss"] <= 100
    else:
        assert payload["aivss"] is None, (
            f"scoring_valid=False scans must publish aivss=None (issue #261); "
            f"got {payload['aivss']!r}"
        )
    # The mode-blind pre-flight estimate is gone; an uncapped run says so.
    assert "cost estimate" not in result.stdout.lower()
    assert "no budget cap" in result.stdout.lower()


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


def test_scan_stub_is_non_authoritative_and_not_evaluated(
    runner: CliRunner, tmp_path: Path
) -> None:
    """A --model stub scan must be flagged NON-AUTHORITATIVE, present a
    NOT_EVALUATED band (no numeric EXCELLENT), and never claim a numeric AIVSS
    in the summary line (#1)."""
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a safe bot.", encoding="utf-8")
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
            "--mode",
            "fast",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    out = result.stdout + (result.stderr or "")
    assert "NON-AUTHORITATIVE" in out
    # QA-G6 (2026-06-03): the CLI summary now humanises the band before
    # printing — ``not_evaluated`` is rendered as ``Not Evaluated (stub
    # mode)`` (see ``agent_guardian.models.severity.humanise_band``). The
    # underscore-bearing enum value must NEVER leak into the operator-
    # facing text. We accept either spelling here so the stub flag still
    # asserts on the surface intent rather than the exact glyph sequence.
    assert "Not Evaluated" in out
    assert "not_evaluated" not in out
    assert "AIVSS=n/a" in out
    assert "band=EXCELLENT" not in out


def test_scan_stub_fail_under_always_fails(runner: CliRunner, tmp_path: Path) -> None:
    """--fail-under on a stub (non-authoritative) scan must FAIL (exit 1),
    never silently pass even at --fail-under 0 (#1)."""
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a safe bot.", encoding="utf-8")
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
            "--mode",
            "fast",
            "--fail-under",
            "0",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_FAIL_UNDER, result.output
    out = result.stdout + (result.stderr or "")
    assert "non-authoritative" in out.lower()


def test_scan_persists_signed_canonical_and_raw_json(runner: CliRunner, tmp_path: Path) -> None:
    """The canonical scan.json is the signed/redacted report (carries an
    ``engine`` block + ``signatures``); a raw model dump is kept as
    scan.raw.json (#1)."""
    prompt = tmp_path / "p.txt"
    prompt.write_text("You are a safe bot.", encoding="utf-8")
    out_path = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--no-tui",
            "--mode",
            "fast",
            "--output-path",
            str(out_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    scan_id = _extract_scan_id_from_summary(result.stdout)
    scan_dir = tmp_path / ".agentguardian" / "scans" / scan_id
    canonical = json.loads((scan_dir / "scan.json").read_text(encoding="utf-8"))
    # Canonical scan.json is the signed report (schema-stamped, has signatures).
    assert "signatures" in canonical
    assert "schema" in canonical
    assert canonical["engine"] == {
        "commander": "stub",
        "attacker": "stub",
        "evaluator": "stub",
    }
    assert canonical["scoring_valid"] is False
    assert canonical["evaluation_mode"] == "stub"
    # The raw, model-roundtrippable dump is alongside.
    assert (scan_dir / "scan.raw.json").is_file()
    raw = json.loads((scan_dir / "scan.raw.json").read_text(encoding="utf-8"))
    assert raw["id"] == scan_id  # raw uses the Scan model field name


def test_report_pdf_requires_output_path(runner: CliRunner, tmp_path: Path) -> None:
    """``report --output pdf`` without --output-path must fail clearly (not
    the old self-contradicting 'pdf is valid then rejected' error) (#18)."""
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
            "--mode",
            "fast",
            "--output-path",
            str(out_path),
        ],
    )
    assert first.exit_code == EXIT_OK
    scan_id = _extract_scan_id_from_summary(first.stdout)
    result = runner.invoke(app, ["report", scan_id, "--output", "pdf"])
    assert result.exit_code == EXIT_CONFIG
    out = result.stdout + (result.stderr or "")
    assert "requires --output-path" in out


def test_report_writes_to_output_path(runner: CliRunner, tmp_path: Path) -> None:
    """``report --output md --output-path FILE`` writes the report to a file
    (the report command gained --output-path) (#18)."""
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
            "--mode",
            "fast",
            "--output-path",
            str(out_path),
        ],
    )
    assert first.exit_code == EXIT_OK
    scan_id = _extract_scan_id_from_summary(first.stdout)
    md_path = tmp_path / "regen.md"
    result = runner.invoke(
        app, ["report", scan_id, "--output", "md", "--output-path", str(md_path)]
    )
    assert result.exit_code == EXIT_OK, result.output
    assert md_path.is_file()
    assert "AIVSS" in md_path.read_text(encoding="utf-8")


def test_report_rejects_unknown_format(runner: CliRunner) -> None:
    """``report --output bogus`` is rejected with EXIT_CONFIG (#18)."""
    result = runner.invoke(app, ["report", "any-id", "--output", "bogus"])
    assert result.exit_code == EXIT_CONFIG
    out = result.stdout + (result.stderr or "")
    assert "unknown output format" in out


def test_verify_no_anchor_refuses_green(runner: CliRunner, tmp_path: Path) -> None:
    """``verify`` with no --pubkey/--secret refuses a green result (#6)."""
    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    path = tmp_path / "report.json"
    write_json(make_scan(), path)
    result = runner.invoke(app, ["verify", str(path)])
    assert result.exit_code != 0
    out = result.stdout + (result.stderr or "")
    assert "UNANCHORED" in out or "UNVERIFIED" in out


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
    # Parse scan_id out of the `scan <id> done: ...` summary line.
    scan_id = _extract_scan_id_from_summary(first.stdout)
    result = runner.invoke(app, ["report", scan_id, "--output", "md"])
    assert result.exit_code == EXIT_OK
    assert "AIVSS" in result.stdout
