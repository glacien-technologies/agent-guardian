"""QA-002 — stdlib-logging routing through RichHandler bound to the shared Console.

The smoking-gun QA-002 regression was a duplicate-frame border tear in
scrollback when a stdlib log line landed during an open ``Live`` block.
The fix routes ``logging`` through :class:`rich.logging.RichHandler`
bound to the same :class:`Console` the Live region holds, so log lines
serialize ABOVE the Live frame rather than racing the renderer.

These tests guard:

* the RichHandler is in fact installed on a TTY,
* ``NO_COLOR=1`` disables it (and strips ANSI),
* repeated ``configure_logging`` calls do not stack handlers,
* logs emitted during a Live block land in scrollback above the panel.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import pytest
from rich.console import Console
from rich.logging import RichHandler

from agent_guardian import logging_setup
from agent_guardian.cli_tui import ScanTUI
from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.logging_setup import _AG_THEME, get_console


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Each test starts with a fresh Console and a clean root logger."""
    logging_setup._reset_for_tests()
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    yield
    logging_setup._reset_for_tests()
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)


def _install_recording_console(monkeypatch: pytest.MonkeyPatch) -> Console:
    """Install a recording Console as the process-wide get_console() return.

    The Console is constructed with ``force_terminal=True`` so RichHandler
    actually emits — the auto-detect would otherwise see the pytest
    capture and back off.
    """
    console = Console(
        record=True,
        width=140,
        force_terminal=True,
        color_system="truecolor",
        theme=_AG_THEME,
    )
    monkeypatch.setattr("agent_guardian.logging_setup._CONSOLE", console)
    return console


def test_richhandler_installed_when_stderr_is_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When stderr is a TTY (and NO_COLOR unset), configure_logging installs RichHandler."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("agent_guardian.logging_setup._stderr_is_tty", lambda: True)
    _install_recording_console(monkeypatch)

    logging_setup.configure_logging(level="INFO", force=True)

    handlers = logging.getLogger().handlers
    assert any(isinstance(h, RichHandler) for h in handlers)


def test_richhandler_bound_to_shared_console(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The installed RichHandler must point at get_console() — that's QA-002's whole point."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("agent_guardian.logging_setup._stderr_is_tty", lambda: True)
    console = _install_recording_console(monkeypatch)

    logging_setup.configure_logging(level="INFO", force=True)

    rich_handler = next(h for h in logging.getLogger().handlers if isinstance(h, RichHandler))
    assert rich_handler.console is console
    assert get_console() is console


def test_no_color_env_disables_rich_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``NO_COLOR=1`` falls back to the plain stream handler (no ANSI in logs)."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr("agent_guardian.logging_setup._stderr_is_tty", lambda: True)

    logging_setup.configure_logging(level="INFO", force=True)

    handlers = logging.getLogger().handlers
    assert not any(isinstance(h, RichHandler) for h in handlers)


def test_repeat_configure_logging_does_not_stack_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three ``configure_logging(force=True)`` calls -> still exactly one RichHandler."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("agent_guardian.logging_setup._stderr_is_tty", lambda: True)
    _install_recording_console(monkeypatch)

    for _ in range(3):
        logging_setup.configure_logging(level="INFO", force=True)

    handlers = logging.getLogger().handlers
    rich_handlers = [h for h in handlers if isinstance(h, RichHandler)]
    assert len(rich_handlers) == 1


def test_log_message_appears_above_live_panel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A log line emitted during a Live block must order BEFORE the panel border."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("agent_guardian.logging_setup._stderr_is_tty", lambda: True)
    console = _install_recording_console(monkeypatch)
    logging_setup.configure_logging(level="INFO", force=True)
    log = logging.getLogger("agent_guardian.tests.qa002")

    async def _run() -> None:
        tui = ScanTUI(
            scan_id="scan-1",
            target_ref="testbench",
            tier="auto",
            console=console,
        )
        async with tui:
            log.info("hello from inside the live region")
            tui.handle_event(
                SwarmEvent(kind="recon_start", timestamp=time.monotonic())  # type: ignore[arg-type]
            )

    asyncio.run(_run())
    text = console.export_text()
    # The log line "hello from inside the live region" must appear in
    # the scrollback BEFORE the final panel border. Rich's Live writes
    # the panel as the trailing frame in the recorded export when the
    # Live exits (with refresh_per_second small enough that no
    # transient frames flush). Assert ordering.
    assert "hello from inside the live region" in text
    log_idx = text.index("hello from inside the live region")
    panel_idx = text.index("AgentGuardian — swarm board")
    assert log_idx < panel_idx, (
        "log line must serialize ABOVE the Live panel as scrollback; "
        f"got log_idx={log_idx}, panel_idx={panel_idx}"
    )


def test_no_color_log_output_has_no_ansi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When NO_COLOR is set the stdlib path is used and no ANSI leaks."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr("agent_guardian.logging_setup._stderr_is_tty", lambda: True)
    import io as _io

    buf = _io.StringIO()
    logging_setup.configure_logging(level="INFO", stream=buf, force=True)
    logging.getLogger("agent_guardian.tests.nocolor").info("plain text")
    assert "\x1b[" not in buf.getvalue()
    assert "plain text" in buf.getvalue()
