"""Tests for the dashboard-server PostHog client.

The client must be a graceful no-op whenever telemetry should not fire --
env-var opt-out, consent opt-out, or a missing project token -- and must
never raise (analytics can never break a dashboard request).
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest

from agent_guardian.server import posthog_client as pc


@pytest.fixture(autouse=True)
def _scrub_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Isolated consent home + scrubbed telemetry/posthog env."""
    monkeypatch.setenv("AGENT_GUARDIAN_HOME", str(tmp_path))  # default-on consent
    monkeypatch.delenv("AGENT_GUARDIAN_TELEMETRY", raising=False)
    monkeypatch.delenv("POSTHOG_PROJECT_TOKEN", raising=False)
    monkeypatch.delenv("POSTHOG_HOST", raising=False)


def test_no_op_when_env_opted_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", "0")
    monkeypatch.setenv("POSTHOG_PROJECT_TOKEN", "phc_test")
    assert pc.build_posthog_client() is None


def test_no_op_when_no_token() -> None:
    # Default-on consent, but no project token configured.
    assert pc.build_posthog_client() is None


def test_no_op_when_consent_opted_out(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_guardian.telemetry.consent import ConsentState, set_consent

    set_consent(ConsentState.OPTED_OUT)
    monkeypatch.setenv("POSTHOG_PROJECT_TOKEN", "phc_test")
    assert pc.build_posthog_client() is None


def test_builds_client_when_token_and_opted_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """With a token and default-on consent, a Posthog instance is returned.

    Construction does no network I/O, so this is safe offline; the host comes
    from POSTHOG_HOST. Exception autocapture MUST be off -- it would ship
    stack traces (file paths, code, locals) and break the anonymity guarantee.
    """
    monkeypatch.setenv("POSTHOG_PROJECT_TOKEN", "phc_test_key")
    monkeypatch.setenv("POSTHOG_HOST", "https://us.i.posthog.com")
    client = pc.build_posthog_client()
    assert client is not None
    assert getattr(client, "enable_exception_autocapture", True) is False
    # Don't leave the SDK's background flush thread running.
    with contextlib.suppress(Exception):
        client.shutdown()


def test_get_posthog_returns_state_or_none() -> None:
    app = SimpleNamespace(state=SimpleNamespace())
    assert pc.get_posthog(app) is None  # type: ignore[arg-type]
    app.state.posthog = "sentinel"
    assert pc.get_posthog(app) == "sentinel"  # type: ignore[arg-type]
