"""CLI tests for the ``doctor --check-connectivity`` flag (#38).

Default behaviour: ``doctor`` detects which provider keys are present in env
but does NOT validate them (zero-cost). With ``--check-connectivity`` set,
``doctor`` probes each detected provider with a minimal request and reports
``ok`` / ``auth-fail`` / ``network-fail`` so the operator can verify the
keys work before a paid scan run.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from typer.testing import CliRunner

from agent_guardian.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
    """Strip every provider key from env + run from a tmpdir so .env can't leak in.

    The CLI's startup callback loads ``./.env`` via python-dotenv, which would
    otherwise repopulate ``GOOGLE_API_KEY`` / ``OPENAI_API_KEY`` from the
    repo-local .env file and trigger real provider calls under respx. We
    chdir to a clean tmp directory for the duration of each test so the
    dotenv loader finds nothing.
    """
    monkeypatch.chdir(tmp_path)  # type: ignore[arg-type]
    for var in (
        "OPENAI_API_KEY",
        "AGENT_GUARDIAN_OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AGENT_GUARDIAN_ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "AGENT_GUARDIAN_GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "AGENT_GUARDIAN_BEDROCK_API_KEY",
        "AGENT_GUARDIAN_VERTEX_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def test_doctor_default_does_not_probe_providers(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without ``--check-connectivity``, doctor must NOT hit the network."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    # If a real HTTP call sneaks out the respx router would log MockNotFound;
    # we assert that doctor never opens an HTTP client when the flag is off.
    with respx.mock(assert_all_called=False) as router:
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "openai" in result.stdout.lower()
        # Must signal "NOT validated" so the operator knows they need the flag.
        assert "not validated" in result.stdout.lower()
        # And no HTTP call was made.
        assert not router.calls


def test_doctor_check_connectivity_reports_ok_on_200(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 200 response from each provider endpoint maps to ``ok``."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.openai.com/v1/models").respond(200, json={"data": []})
        result = runner.invoke(app, ["doctor", "--check-connectivity"])
        assert result.exit_code == 0, result.stdout
        # Connectivity line uses the canonical "ok" label.
        assert "openai connectivity: ok" in result.stdout.lower()


def test_doctor_check_connectivity_reports_auth_fail_on_401(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 401 from a provider maps to ``auth-fail``."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-bad")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.openai.com/v1/models").respond(401)
        result = runner.invoke(app, ["doctor", "--check-connectivity"])
        assert result.exit_code == 0
        assert "openai connectivity: auth-fail" in result.stdout.lower()


def test_doctor_check_connectivity_reports_network_fail_on_transport_error(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transport error (timeout, DNS, refused) maps to ``network-fail``."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.openai.com/v1/models").mock(
            side_effect=httpx.ConnectError("simulated")
        )
        result = runner.invoke(app, ["doctor", "--check-connectivity"])
        assert result.exit_code == 0
        assert "openai connectivity: network-fail" in result.stdout.lower()
