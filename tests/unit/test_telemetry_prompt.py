"""Tests for the telemetry first-run enable flow.

Default-on / opt-out policy: telemetry is **on by default** on a fresh
install. :func:`maybe_prompt_consent` transitions ``NOT_PROMPTED`` ->
``EXTENDED`` silently and emits one :class:`InstallEvent`, unless an
explicit opt-out is in force (``AGENT_GUARDIAN_TELEMETRY=0`` / ``off`` /
``false`` / ``no``). There is no consent prompt and no CI carve-out.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.telemetry.consent import (
    ConsentState,
    get_consent,
    set_consent,
)
from agent_guardian.telemetry.prompt import maybe_prompt_consent


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh ~/.agentguardian sandbox + scrubbed telemetry env var."""
    monkeypatch.setenv("AGENT_GUARDIAN_HOME", str(tmp_path))
    monkeypatch.delenv("AGENT_GUARDIAN_TELEMETRY", raising=False)


@pytest.fixture
def _install_events(monkeypatch: pytest.MonkeyPatch) -> list[None]:
    """Capture _emit_install_event calls without hitting the client."""
    calls: list[None] = []
    monkeypatch.setattr(
        "agent_guardian.telemetry.prompt._emit_install_event",
        lambda: calls.append(None),
    )
    return calls


# ---------------------------------------------------------------------------
# Existing-decision noop
# ---------------------------------------------------------------------------


def test_noop_when_state_is_decided(_install_events: list[None]) -> None:
    """A decision already on file makes the call a noop (no re-enable, no event)."""
    for state in (
        ConsentState.ESSENTIAL,
        ConsentState.EXTENDED,
        ConsentState.OPTED_OUT,
        ConsentState.OPTED_IN,
        ConsentState.DEFERRED,
    ):
        set_consent(state)
        assert maybe_prompt_consent() is state
        assert _install_events == []


# ---------------------------------------------------------------------------
# AGENT_GUARDIAN_TELEMETRY env-var resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["off", "0", "false", "no", "OFF", " No "])
def test_env_off_values_persist_opted_out(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _install_events: list[None],
) -> None:
    """The opt-out env values persist OPTED_OUT and emit nothing."""
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", value)
    assert maybe_prompt_consent() is ConsentState.OPTED_OUT
    assert get_consent() is ConsentState.OPTED_OUT
    assert "telemetry" in capsys.readouterr().err.lower()
    assert _install_events == []  # OPTED_OUT never sends an InstallEvent


@pytest.mark.parametrize(
    "value, expected",
    [
        ("essential", ConsentState.ESSENTIAL),
        ("extended", ConsentState.EXTENDED),
        ("EXTENDED", ConsentState.EXTENDED),
        # Default tier is EXTENDED, so the generic truthy values map there too.
        ("on", ConsentState.EXTENDED),
        ("1", ConsentState.EXTENDED),
        ("true", ConsentState.EXTENDED),
        ("yes", ConsentState.EXTENDED),
        ("YES", ConsentState.EXTENDED),
    ],
)
def test_env_on_values_persist_tier(
    value: str,
    expected: ConsentState,
    monkeypatch: pytest.MonkeyPatch,
    _install_events: list[None],
) -> None:
    """Explicit env tiers persist the requested tier and emit one InstallEvent."""
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", value)
    assert maybe_prompt_consent() is expected
    assert get_consent() is expected
    assert _install_events == [None]


def test_env_unknown_value_falls_through_to_default_on(
    monkeypatch: pytest.MonkeyPatch,
    _install_events: list[None],
) -> None:
    """An unrecognised env value is ignored; the default-on path enables EXTENDED."""
    monkeypatch.setenv("AGENT_GUARDIAN_TELEMETRY", "maybe-later")
    assert maybe_prompt_consent() is ConsentState.EXTENDED
    assert get_consent() is ConsentState.EXTENDED
    assert _install_events == [None]


# ---------------------------------------------------------------------------
# Default-on: a fresh install enables silently (no prompt, no CI carve-out)
# ---------------------------------------------------------------------------


def test_fresh_install_enables_extended_and_emits(_install_events: list[None]) -> None:
    """No consent file + no env override -> EXTENDED + exactly one InstallEvent."""
    assert get_consent() is ConsentState.NOT_PROMPTED
    assert maybe_prompt_consent() is ConsentState.EXTENDED
    assert get_consent() is ConsentState.EXTENDED
    assert _install_events == [None]


@pytest.mark.parametrize("var", ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_HOME"])
def test_default_on_applies_in_ci(
    var: str,
    monkeypatch: pytest.MonkeyPatch,
    _install_events: list[None],
) -> None:
    """Default-on has no CI/non-interactive carve-out -- a pipeline scan still counts."""
    monkeypatch.setenv(var, "1")
    assert maybe_prompt_consent() is ConsentState.EXTENDED
    assert get_consent() is ConsentState.EXTENDED
    assert _install_events == [None]


def test_force_re_enables_after_reset(_install_events: list[None]) -> None:
    """force=True (used by `telemetry reset`) re-enables from a decided state."""
    set_consent(ConsentState.OPTED_OUT)
    assert maybe_prompt_consent(force=True) is ConsentState.EXTENDED
    assert get_consent() is ConsentState.EXTENDED
    assert _install_events == [None]


# ---------------------------------------------------------------------------
# Default-ON integration -- the headline assertion
# ---------------------------------------------------------------------------


def test_fresh_install_is_on_by_default() -> None:
    """Before anything runs, a fresh install reports on (extended tier)."""
    from agent_guardian.telemetry.consent import consent_level, is_opted_in

    assert get_consent() is ConsentState.NOT_PROMPTED
    assert is_opted_in() is True
    assert consent_level() == "extended"
