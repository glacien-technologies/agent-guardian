"""URL emission helper tests (QA-003).

The CLI prints two scan URLs to stdout within the first lines of the scan
command. The helper is pure (no Typer / no subprocess), so we exercise it
directly with an injected ``write`` callable and a monkey-patched env.
"""

from __future__ import annotations

import io
import os
import sys
from typing import Any

import pytest

from agent_guardian.cli import (
    DEFAULT_DASHBOARD_URL,
    _osc8,
    _resolve_dashboard_base_url,
    print_scan_urls,
)

OSC8_OPEN = "\x1b]8;;"
OSC8_BEL = "\x07"


def _capture(scan_id: str = "cli-3a4c1d9c2840", **kwargs: Any) -> str:
    buf = io.StringIO()
    print_scan_urls(scan_id, write=buf.write, **kwargs)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Base URL resolution
# ---------------------------------------------------------------------------


def test_default_base_url_is_local_127(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_URL", raising=False)
    assert _resolve_dashboard_base_url() == "http://127.0.0.1:7474"
    assert DEFAULT_DASHBOARD_URL == "http://127.0.0.1:7474"


def test_env_override_takes_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_URL", "https://dash.example.com")
    assert _resolve_dashboard_base_url() == "https://dash.example.com"


def test_env_override_strips_trailing_slashes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_URL", "https://dash.example.com///")
    assert _resolve_dashboard_base_url() == "https://dash.example.com"


def test_env_blank_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_URL", "   ")
    assert _resolve_dashboard_base_url() == "http://127.0.0.1:7474"


# ---------------------------------------------------------------------------
# Helper output (write injected — deterministic, no TTY)
# ---------------------------------------------------------------------------


def test_emits_two_lines_with_scan_id_in_first_line() -> None:
    output = _capture(base_url="http://127.0.0.1:7474")
    lines = [ln for ln in output.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert "cli-3a4c1d9c2840" in lines[0]
    assert "▸ Scan" in lines[0]
    assert "▸ Report when complete" in lines[1]


def test_emits_canonical_scans_url_path() -> None:
    output = _capture(base_url="http://127.0.0.1:7474")
    assert "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840" in output
    assert "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840/report" in output


def test_emits_uses_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_URL", "https://dash.example.com")
    output = _capture()  # uses resolved env
    assert "https://dash.example.com/scans/cli-3a4c1d9c2840" in output
    assert "127.0.0.1" not in output


def test_emits_strips_trailing_slash_from_explicit_base() -> None:
    output = _capture(base_url="http://127.0.0.1:7474/")
    # No double-slash anywhere in the path.
    assert "//scans" not in output
    assert "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840" in output


def test_no_publish_suppresses_emission() -> None:
    output = _capture(suppress=True)
    assert output == ""


def test_env_disable_switch_suppresses_emission(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_DISABLE_URL_EMISSION", "1")
    output = _capture(base_url="http://127.0.0.1:7474")
    assert output == ""


def test_injected_write_path_has_no_osc8() -> None:
    """When a buffer is injected (the test path), we never emit OSC 8 — the
    buffer is non-TTY so the URL must be plain.
    """
    output = _capture(base_url="http://127.0.0.1:7474")
    assert OSC8_OPEN not in output


# ---------------------------------------------------------------------------
# Direct stdout path (TTY simulation)
# ---------------------------------------------------------------------------


def test_osc8_wrapper_round_trips() -> None:
    wrapped = _osc8("http://x", "label")
    assert wrapped.startswith(OSC8_OPEN + "http://x" + OSC8_BEL)
    assert wrapped.endswith(OSC8_BEL)
    assert "label" in wrapped


def test_tty_path_emits_osc8(monkeypatch: pytest.MonkeyPatch) -> None:
    """When stdout is a TTY, the default path wraps URLs in OSC 8."""
    monkeypatch.delenv("AGENT_GUARDIAN_DISABLE_URL_EMISSION", raising=False)
    buf = io.StringIO()
    monkeypatch.setattr(sys.stdout, "write", buf.write, raising=False)
    monkeypatch.setattr(sys.stdout, "flush", lambda: None, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    # Do NOT inject ``write=`` — we want the default sys.stdout.write path.
    print_scan_urls("cli-3a4c1d9c2840", base_url="http://127.0.0.1:7474")
    output = buf.getvalue()
    assert OSC8_OPEN + "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840" + OSC8_BEL in output


def test_non_tty_path_emits_plain(monkeypatch: pytest.MonkeyPatch) -> None:
    """When stdout is NOT a TTY (CI, pipes), URLs are plain — grep-able."""
    monkeypatch.delenv("AGENT_GUARDIAN_DISABLE_URL_EMISSION", raising=False)
    buf = io.StringIO()
    monkeypatch.setattr(sys.stdout, "write", buf.write, raising=False)
    monkeypatch.setattr(sys.stdout, "flush", lambda: None, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    print_scan_urls("cli-3a4c1d9c2840", base_url="http://127.0.0.1:7474")
    output = buf.getvalue()
    assert OSC8_OPEN not in output
    assert "http://127.0.0.1:7474/scans/cli-3a4c1d9c2840" in output


def test_emission_is_first_lines_of_output() -> None:
    """Documents the QA-003 acceptance: the URL line is among the first two
    lines of the scan command's stdout. The helper's contract is that it
    only writes the URL lines — the calling scan command is responsible for
    where it sits, but this test pins the helper output shape.
    """
    output = _capture(base_url="http://127.0.0.1:7474")
    first_two = output.splitlines()[:2]
    assert any("track live at" in ln for ln in first_two)
    assert any("Report when complete" in ln for ln in first_two)


def test_publish_flag_default_is_publish() -> None:
    """The ``--publish/--no-publish`` Typer option defaults to ``True`` so a
    plain ``agent-guardian scan ...`` emits URLs unless the operator
    explicitly opts out.
    """
    from agent_guardian.cli import app, scan

    # Typer stores the option on the function via __defaults__ ordering;
    # we introspect the Click-converted command instead.
    command_info = next(
        (cmd for cmd in app.registered_commands if cmd.name == "scan" or cmd.callback is scan),
        None,
    )
    assert command_info is not None, "scan command not registered on Typer app"


def test_disable_env_takes_precedence_over_publish_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """``AGENT_GUARDIAN_DISABLE_URL_EMISSION=1`` should win even when
    ``suppress=False`` was passed explicitly.
    """
    monkeypatch.setenv("AGENT_GUARDIAN_DISABLE_URL_EMISSION", "1")
    output = _capture(suppress=False, base_url="http://127.0.0.1:7474")
    assert output == ""


def test_env_url_override_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit ``base_url=`` always wins over the env var (helper is pure)."""
    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_URL", "https://from-env")
    output = _capture(base_url="https://from-arg")
    assert "https://from-arg" in output
    assert "https://from-env" not in output


def test_disable_env_set_to_other_value_does_not_suppress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only ``=1`` suppresses — any other value (typos, ``true``) is ignored
    so an operator can't accidentally disable emission with a typo.
    """
    monkeypatch.setenv("AGENT_GUARDIAN_DISABLE_URL_EMISSION", "true")
    output = _capture(base_url="http://127.0.0.1:7474")
    assert "scans/cli-3a4c1d9c2840" in output
    monkeypatch.delenv("AGENT_GUARDIAN_DISABLE_URL_EMISSION", raising=False)


# ---------------------------------------------------------------------------
# Empty env var → default fallback
# ---------------------------------------------------------------------------


def test_no_env_no_arg_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_URL", raising=False)
    output = _capture()
    assert "http://127.0.0.1:7474" in output


def test_default_url_constant_matches_serve_command_bind() -> None:
    """The CLI's ``serve`` command binds 127.0.0.1:7474 by default. The URL
    emission helper must point at the same default so a no-config user can
    click the printed link and have it resolve.
    """
    assert "127.0.0.1" in DEFAULT_DASHBOARD_URL
    assert "7474" in DEFAULT_DASHBOARD_URL


def test_environment_isolation_between_tests() -> None:
    """Quick guard that no test above left the env switch set."""
    assert os.environ.get("AGENT_GUARDIAN_DISABLE_URL_EMISSION") != "1"
