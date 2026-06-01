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


def test_list_probes_prints_full_corpus(runner: CliRunner) -> None:
    result = runner.invoke(app, ["list-probes"])
    assert result.exit_code == 0
    # M11 shipped 50 bundled probes; Phase B added 29 OWASP-2026-aligned
    # probes; the production-hardening pass added 11 more (ASI04/06/09
    # coverage for poisoned checkpoints, sign-off spoofing, validator
    # bypass, denial-of-wallet, recursion / fan-out abuse, etc.); the
    # M2 LLM02 specialist pass added 2 output-handling canary probes;
    # GAP-3 (2026-05-30) added 1 ASI03 cross-tenant PII probe for a
    # subtotal of 96 attack probes. Phase A.A4 added 4 JDG-* judge-
    # evaluation probes (separate namespace, not part of the AIVSS
    # attack score) for a current total of 100. The corpus-version
    # stamp is also printed.
    assert "Probe corpus version" in result.stdout
    # Phase B.B5 added 3 ASI01 H-CoT probes -> 99 attack + 4 judge = 103 total.
    assert "Found 103 probes" in result.stdout
    # At least one ID from each category should appear.
    for asi in ("ASI01", "ASI02", "ASI05", "ASI10"):
        assert asi in result.stdout


def test_list_probes_with_asi_filter(runner: CliRunner) -> None:
    result = runner.invoke(app, ["list-probes", "--asi", "ASI01"])
    assert result.exit_code == 0
    # ASI01 has 5 original + 3 Phase-B probes + 1 persona-break probe added in
    # the scoring-trust belt-and-suspenders pass = 9 attack probes. Phase
    # A.A4 added 3 JDG-* judge-evaluation probes tagged with asi=ASI01
    # (defended-marker-injection + paraphrase-consistency + calibration-set)
    # for a subtotal of 12. Phase B.B5 added 3 ASI01 H-CoT injection probes
    # for a current total of 15.
    assert "Found 15 probes (filtered by ASI01)" in result.stdout
    assert "ASI02" not in result.stdout


def test_list_probes_with_invalid_asi_filter(runner: CliRunner) -> None:
    result = runner.invoke(app, ["list-probes", "--asi", "BOGUS"])
    assert result.exit_code != 0


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
    # Ed25519 integrity holds + pin matches -> anchored & green; HMAC fails
    # closed (default secret never trusted) but does not veto the pinned anchor.
    assert result.exit_code == 0, (result.stdout, result.stderr)
    assert "PINNED" in result.stdout
    assert "Ed25519:      OK" in result.stdout
    assert "HMAC-SHA256:  FAIL" in result.stdout


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


def test_publish_missing_scan_errors_out(runner: CliRunner) -> None:
    """Publishing a non-existent scan must exit with the config exit code."""
    result = runner.invoke(app, ["publish", "no-such-scan"])
    assert result.exit_code == EXIT_CONFIG
    # Error messages go to stderr; ``result.output`` aggregates whichever
    # stream the command actually wrote to.
    assert "no scan found" in (result.stderr or result.output)


def test_publish_redacts_transcripts_and_prints_manual_message(
    runner: CliRunner, tmp_path: Path
) -> None:
    """The publish flow must (a) refuse unsigned scans implicitly via verify
    (b) strip transcript_ref + transcript from each finding, and (c) print
    the manual-submission placeholder pointing at the GitHub issue tracker."""
    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    scan_path = tmp_path / "report.json"
    write_json(make_scan(), scan_path)

    # Sprinkle a fake transcript ref into the emitted JSON so we can prove
    # redaction happens. (The emitter already redacts PII inside ``summary``.)
    payload = json.loads(scan_path.read_text(encoding="utf-8"))
    for finding in payload["findings"]:
        finding["transcript_ref"] = "/tmp/super-secret-trace.json"
        finding["transcript"] = "USER: my email is leaky@example.com\nBOT: ..."
    scan_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    out_path = tmp_path / "leaderboard.json"
    result = runner.invoke(app, ["publish", str(scan_path), "--output", str(out_path)])

    # NB: because we mutated the payload above the M13 signature no longer
    # matches; the command exits with EXIT_FAIL_UNDER in that case. To prove
    # the happy path we re-emit a fresh signed scan with transcripts:
    if result.exit_code != EXIT_OK:
        # Re-sign with the tampered transcripts.
        from agent_guardian.reports.json_report import sign_payload

        payload = json.loads(scan_path.read_text(encoding="utf-8"))
        payload.pop("signatures", None)
        payload["signatures"] = sign_payload(payload)
        scan_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        result = runner.invoke(app, ["publish", str(scan_path), "--output", str(out_path)])

    assert result.exit_code == EXIT_OK, result.stdout
    assert "Leaderboard endpoint not yet deployed" in result.stdout
    assert "github.com/glacien-technologies/agent-guardian/issues" in result.stdout

    # Redacted output must not contain transcripts or the original signature.
    redacted = json.loads(out_path.read_text(encoding="utf-8"))
    assert "signatures" not in redacted, "signatures must be stripped"
    for finding in redacted["findings"]:
        assert "transcript_ref" not in finding, "transcript_ref must be stripped"
        assert "transcript" not in finding, "transcript must be stripped"


def test_publish_rejects_unsigned_scan(runner: CliRunner, tmp_path: Path) -> None:
    """A scan without ``signatures`` must be refused — we never publish what
    we cannot prove came from the local install."""
    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    scan_path = tmp_path / "report.json"
    write_json(make_scan(), scan_path)
    payload = json.loads(scan_path.read_text(encoding="utf-8"))
    payload.pop("signatures", None)
    scan_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    result = runner.invoke(app, ["publish", str(scan_path)])
    assert result.exit_code == EXIT_CONFIG
    assert "not signed" in (result.stderr or result.output)


def test_publish_rejects_tampered_scan(runner: CliRunner, tmp_path: Path) -> None:
    """A scan whose signatures don't verify must be refused with exit-1."""
    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    scan_path = tmp_path / "report.json"
    write_json(make_scan(), scan_path)
    payload = json.loads(scan_path.read_text(encoding="utf-8"))
    # Tamper with a scored field — signatures will fail.
    payload["aivss"] = 0
    scan_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    result = runner.invoke(app, ["publish", str(scan_path)])
    assert result.exit_code == EXIT_FAIL_UNDER
    assert "signature verification failed" in (result.stderr or result.output)


def test_publish_rejects_non_object_json(runner: CliRunner, tmp_path: Path) -> None:
    """A JSON file whose top level is a list (or anything non-object) must be
    refused before signature verification runs."""
    scan_path = tmp_path / "report.json"
    scan_path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    result = runner.invoke(app, ["publish", str(scan_path)])
    assert result.exit_code == EXIT_CONFIG
    assert "not a JSON object" in (result.stderr or result.output)


def test_publish_resolves_scan_id_to_scan_json_fallback(runner: CliRunner, tmp_path: Path) -> None:
    """When the scan-id directory has scan.json but not report.json, the
    publish command must fall back gracefully."""
    from agent_guardian.reports.json_report import write_json
    from tests.unit._report_fixtures import make_scan

    scan_id = "cli-fallback-test"
    # The autouse fixture pins HOME to tmp_path so this lands inside the
    # isolated tree.
    scan_dir = tmp_path / ".agentguardian" / "scans" / scan_id
    scan_dir.mkdir(parents=True)
    write_json(make_scan(), scan_dir / "scan.json")

    result = runner.invoke(app, ["publish", scan_id])
    assert result.exit_code == EXIT_OK, (result.stdout, result.stderr)
    assert "Leaderboard endpoint not yet deployed" in result.stdout
    # The redacted payload landed alongside scan.json.
    assert (scan_dir / "leaderboard.json").is_file()


def test_publish_truncates_oversize_finding_summary(runner: CliRunner, tmp_path: Path) -> None:
    """Any finding whose ``summary`` somehow exceeds 280 chars (custom emitter)
    must be hard-capped before the redacted payload is written."""
    from agent_guardian.reports.json_report import sign_payload, write_json
    from tests.unit._report_fixtures import make_scan

    scan_path = tmp_path / "report.json"
    write_json(make_scan(), scan_path)
    payload = json.loads(scan_path.read_text(encoding="utf-8"))
    long_summary = "A" * 600  # Well above the 280 char cap.
    payload["findings"][0]["summary"] = long_summary
    # Re-sign so verify passes.
    payload.pop("signatures", None)
    payload["signatures"] = sign_payload(payload)
    scan_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    out_path = tmp_path / "leaderboard.json"
    result = runner.invoke(app, ["publish", str(scan_path), "--output", str(out_path)])
    assert result.exit_code == EXIT_OK, (result.stdout, result.stderr)
    redacted = json.loads(out_path.read_text(encoding="utf-8"))
    summary = redacted["findings"][0]["summary"]
    assert len(summary) <= 280
    assert summary.endswith("...")


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
    assert 0 <= payload["aivss"] <= 100
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
    assert "not_evaluated" in out
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
    scan_id = result.stdout.strip().splitlines()[-1].split()[1]
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
    scan_id = first.stdout.strip().splitlines()[-1].split()[1]
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
    scan_id = first.stdout.strip().splitlines()[-1].split()[1]
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
    # Parse scan_id out of the summary line.
    summary = first.stdout.strip().splitlines()[-1]
    scan_id = summary.split()[1]
    result = runner.invoke(app, ["report", scan_id, "--output", "md"])
    assert result.exit_code == EXIT_OK
    assert "AIVSS" in result.stdout
