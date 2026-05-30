"""Tests for the telemetry consent prompt + first-scan flow.

These tests enforce the launch-readiness audit BLOCKER: telemetry must
be **off by default** on a fresh install. The prompt should only
transition NOT_PROMPTED → ESSENTIAL when the user (or env var) gives
positive consent; every other path persists OPTED_OUT and emits zero
network traffic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_guardian.telemetry.consent import (
    ConsentState,
    get_consent,
    set_consent,
)
from agent_guardian.telemetry.prompt import (
    CONSENT_PROMPT_QUESTION,
    maybe_prompt_consent,
)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh ~/.agentguardian sandbox + scrubbed telemetry env vars."""
    monkeypatch.setenv("AGENT_GUARDIAN_HOME", str(tmp_path))
    monkeypatch.delenv("AGENT_GUARDIAN_TELEMETRY", raising=False)
    # Scrub CI markers so the non-interactive path is exercised only
    # when a test explicitly opts in.
    for var in (
        "CI",
        "CONTINUOUS_INTEGRATION",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "BUILDKITE",
        "CIRCLECI",
        "TRAVIS",
        "JENKINS_HOME",
        "TF_BUILD",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def _no_install_event(monkeypatch: pytest.MonkeyPatch) -> list[None]:
    """Capture calls to _emit_install_event so tests can assert on them
    without actually hitting the telemetry client."""
    calls: list[None] = []

    def fake_emit() -> None:
        calls.append(None)

    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._emit_install_event",
        fake_emit,
    )
    return calls


# ---------------------------------------------------------------------------
# Existing-decision noop
# ---------------------------------------------------------------------------


def test_noop_when_state_is_not_not_prompted(
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """If a decision is already on file, the prompt is a noop."""

    def boom(*_a: Any, **_kw: Any) -> bool:
        raise AssertionError("typer.confirm must not be called when state is decided")

    monkeypatch.setattr("typer.confirm", boom)

    for state in (
        ConsentState.ESSENTIAL,
        ConsentState.EXTENDED,
        ConsentState.OPTED_OUT,
        ConsentState.OPTED_IN,
        ConsentState.DEFERRED,
    ):
        set_consent(state)
        assert maybe_prompt_consent() is state
        # No InstallEvent should fire when we're in noop mode.
        assert _no_install_event == []


# ---------------------------------------------------------------------------
# AGENT_GUARDIAN_TELEMETRY env-var resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["off", "0", "false", "no", "OFF", " No "])
def test_env_off_values_persist_opted_out(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _no_install_event: list[None],
) -> None:
    """The opt-out env values short-circuit before any prompt fires."""

    def boom(*_a: Any, **_kw: Any) -> bool:
        raise AssertionError("env-var opt-out must not invoke typer.confirm")

    monkeypatch.setattr("typer.confirm", boom)
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", value)
    assert maybe_prompt_consent() is ConsentState.OPTED_OUT
    assert get_consent() is ConsentState.OPTED_OUT
    err = capsys.readouterr().err
    assert "telemetry" in err.lower()
    assert _no_install_event == []  # OPTED_OUT never sends an InstallEvent


@pytest.mark.parametrize(
    "value, expected",
    [
        ("essential", ConsentState.ESSENTIAL),
        ("on", ConsentState.ESSENTIAL),
        ("1", ConsentState.ESSENTIAL),
        ("true", ConsentState.ESSENTIAL),
        ("yes", ConsentState.ESSENTIAL),
        ("YES", ConsentState.ESSENTIAL),
        ("extended", ConsentState.EXTENDED),
        ("EXTENDED", ConsentState.EXTENDED),
    ],
)
def test_env_on_values_persist_positive_tier(
    value: str,
    expected: ConsentState,
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """The opt-in env values persist the requested tier and emit InstallEvent."""

    def boom(*_a: Any, **_kw: Any) -> bool:
        raise AssertionError("env-var opt-in must not invoke typer.confirm")

    monkeypatch.setattr("typer.confirm", boom)
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", value)
    assert maybe_prompt_consent() is expected
    assert get_consent() is expected
    assert _no_install_event == [None]


def test_env_unknown_value_falls_through_to_prompt(
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """An unrecognised env value is not silently honoured -- the prompt fires."""
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", "maybe-later")
    # Pretend we're interactive so the prompt path is reachable.
    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._is_non_interactive",
        lambda: False,
    )

    answered: list[Any] = []

    def fake_confirm(prompt: str, *, default: bool = False) -> bool:
        answered.append((prompt, default))
        return False

    monkeypatch.setattr("typer.confirm", fake_confirm)
    assert maybe_prompt_consent() is ConsentState.OPTED_OUT
    assert answered == [(CONSENT_PROMPT_QUESTION, False)]


# ---------------------------------------------------------------------------
# Non-interactive / CI runs default to OPTED_OUT
# ---------------------------------------------------------------------------


def test_non_interactive_persists_opted_out(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _no_install_event: list[None],
) -> None:
    """A non-TTY run never blocks on a prompt -- it persists OPTED_OUT."""

    def boom(*_a: Any, **_kw: Any) -> bool:
        raise AssertionError("non-interactive run must not call typer.confirm")

    monkeypatch.setattr("typer.confirm", boom)
    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._is_non_interactive",
        lambda: True,
    )
    assert maybe_prompt_consent() is ConsentState.OPTED_OUT
    err = capsys.readouterr().err
    assert "off" in err.lower()
    assert _no_install_event == []


@pytest.mark.parametrize(
    "var",
    [
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "BUILDKITE",
        "CIRCLECI",
        "TRAVIS",
        "JENKINS_HOME",
        "TF_BUILD",
    ],
)
def test_ci_env_markers_force_non_interactive(
    var: str,
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """Standard CI env vars route to the non-interactive OPTED_OUT path."""

    def boom(*_a: Any, **_kw: Any) -> bool:
        raise AssertionError(f"{var} should force non-interactive path")

    monkeypatch.setattr("typer.confirm", boom)
    monkeypatch.setenv(var, "1")
    assert maybe_prompt_consent() is ConsentState.OPTED_OUT
    assert _no_install_event == []


# ---------------------------------------------------------------------------
# Interactive prompt: yes/no flows
# ---------------------------------------------------------------------------


def test_interactive_yes_persists_essential_and_emits_install(
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """A positive answer to the prompt persists ESSENTIAL and fires InstallEvent."""
    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._is_non_interactive",
        lambda: False,
    )

    answered: list[tuple[str, bool]] = []

    def fake_confirm(prompt: str, *, default: bool = False) -> bool:
        answered.append((prompt, default))
        return True

    monkeypatch.setattr("typer.confirm", fake_confirm)
    assert maybe_prompt_consent() is ConsentState.ESSENTIAL
    assert get_consent() is ConsentState.ESSENTIAL
    # Default MUST be False -- the user has to actively say yes.
    assert answered == [(CONSENT_PROMPT_QUESTION, False)]
    assert _no_install_event == [None]


def test_interactive_no_persists_opted_out(
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """A negative answer persists OPTED_OUT and emits nothing."""
    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._is_non_interactive",
        lambda: False,
    )
    monkeypatch.setattr("typer.confirm", lambda *_a, **_kw: False)
    assert maybe_prompt_consent() is ConsentState.OPTED_OUT
    assert get_consent() is ConsentState.OPTED_OUT
    assert _no_install_event == []


def test_interactive_abort_treated_as_no(
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """A KeyboardInterrupt / EOFError / typer.Abort defaults to OPTED_OUT.

    Pressing Ctrl-C at the prompt must NOT silently opt the user in.
    """
    import typer

    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._is_non_interactive",
        lambda: False,
    )

    def aborting(*_a: Any, **_kw: Any) -> bool:
        raise typer.Abort()

    monkeypatch.setattr("typer.confirm", aborting)
    assert maybe_prompt_consent() is ConsentState.OPTED_OUT
    assert get_consent() is ConsentState.OPTED_OUT
    assert _no_install_event == []


def test_force_reprompts_after_reset(
    monkeypatch: pytest.MonkeyPatch,
    _no_install_event: list[None],
) -> None:
    """force=True lets `telemetry reset` re-ask even if a decision exists."""
    set_consent(ConsentState.OPTED_OUT)
    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._is_non_interactive",
        lambda: False,
    )
    monkeypatch.setattr("typer.confirm", lambda *_a, **_kw: True)
    assert maybe_prompt_consent(force=True) is ConsentState.ESSENTIAL
    assert get_consent() is ConsentState.ESSENTIAL
    assert _no_install_event == [None]


# ---------------------------------------------------------------------------
# Default-OFF integration -- the headline BLOCKER assertion
# ---------------------------------------------------------------------------


def test_fresh_install_is_off_until_prompt_runs() -> None:
    """Before anything runs, a fresh install reports off."""
    from agent_guardian.telemetry.consent import consent_level, is_opted_in

    assert get_consent() is ConsentState.NOT_PROMPTED
    assert is_opted_in() is False
    assert consent_level() == "off"
