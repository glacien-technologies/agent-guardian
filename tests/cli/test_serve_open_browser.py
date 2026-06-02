"""Unit tests for the ``agent-guardian serve`` auto-open-browser hook (Fix L).

The serve command opens the dashboard URL in the operator's default browser
once the port binds, so the operator doesn't have to alt-tab to a terminal to
grab the URL. The behaviour is opt-out via ``--no-open`` and additionally
auto-skipped in headless environments (CI, SSH, non-TTY) so it's safe to
leave on by default.

This suite drives the gating logic directly — no real ``uvicorn.run`` is
spawned. Integration of the threaded poll-then-open helper is exercised by
mocking ``socket.create_connection`` so the wait loop terminates
deterministically.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest

from agent_guardian.cli import _maybe_open_browser, _wait_for_port_then_open

# ---------------------------------------------------------------------------
# _maybe_open_browser — direct gating tests
# ---------------------------------------------------------------------------


def test_maybe_open_browser_opens_when_requested_and_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: requested + TTY + no headless markers → open is called."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    with mock.patch("webbrowser.open_new_tab") as opener:
        _maybe_open_browser("http://127.0.0.1:7474/", requested=True)

    opener.assert_called_once_with("http://127.0.0.1:7474/")


def test_maybe_open_browser_skipped_when_not_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--no-open`` short-circuits before any env probing."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    with mock.patch("webbrowser.open_new_tab") as opener:
        _maybe_open_browser("http://127.0.0.1:7474/", requested=False)

    opener.assert_not_called()


def test_maybe_open_browser_skipped_under_ci(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``CI=1`` is the universal headless marker — never opens a browser."""
    monkeypatch.setenv("CI", "1")
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    with mock.patch("webbrowser.open_new_tab") as opener:
        _maybe_open_browser("http://127.0.0.1:7474/", requested=True)

    opener.assert_not_called()


def test_maybe_open_browser_skipped_under_ssh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SSH sessions don't have an X server — never opens a browser."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.1 55555 10.0.0.2 22")
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    with mock.patch("webbrowser.open_new_tab") as opener:
        _maybe_open_browser("http://127.0.0.1:7474/", requested=True)

    opener.assert_not_called()


def test_maybe_open_browser_skipped_when_not_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pipe-to-file / log capture / nohup — no TTY → no browser."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: False)

    with mock.patch("webbrowser.open_new_tab") as opener:
        _maybe_open_browser("http://127.0.0.1:7474/", requested=True)

    opener.assert_not_called()


def test_maybe_open_browser_swallows_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A browser-launch failure must never crash the serve process."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    def _boom(_url: str) -> None:
        raise RuntimeError("browser missing")

    with mock.patch("webbrowser.open_new_tab", side_effect=_boom):
        # Must not raise.
        _maybe_open_browser("http://127.0.0.1:7474/", requested=True)


# ---------------------------------------------------------------------------
# _wait_for_port_then_open — poll-then-open path
# ---------------------------------------------------------------------------


def test_wait_for_port_then_open_fires_when_port_binds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``socket.create_connection`` returns, the browser is opened.

    Drives the helper without spawning a real listener — the mocked socket
    simulates an immediately-bound port.
    """
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    fake_conn = mock.MagicMock()
    fake_conn.__enter__ = mock.MagicMock(return_value=fake_conn)
    fake_conn.__exit__ = mock.MagicMock(return_value=False)

    with (
        mock.patch("socket.create_connection", return_value=fake_conn) as connect,
        mock.patch("webbrowser.open_new_tab") as opener,
    ):
        _wait_for_port_then_open("127.0.0.1", 7474, requested=True, path="/")

    connect.assert_called_once_with(("127.0.0.1", 7474), timeout=0.2)
    opener.assert_called_once_with("http://127.0.0.1:7474/")


def test_wait_for_port_then_open_skipped_when_not_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--no-open`` short-circuits before any socket probing."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    with (
        mock.patch("socket.create_connection") as connect,
        mock.patch("webbrowser.open_new_tab") as opener,
    ):
        _wait_for_port_then_open("127.0.0.1", 7474, requested=False, path="/")

    connect.assert_not_called()
    opener.assert_not_called()


def test_wait_for_port_then_open_quiet_on_bind_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the port never opens within 5 retries, no browser is opened."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)
    # Speed up the test — the helper sleeps 200 ms between retries; patch
    # ``time.sleep`` to a no-op so the suite stays fast.
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)

    def _refused(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("connection refused")

    with (
        mock.patch("socket.create_connection", side_effect=_refused) as connect,
        mock.patch("webbrowser.open_new_tab") as opener,
    ):
        _wait_for_port_then_open("127.0.0.1", 7474, requested=True, path="/")

    # 5 retries before giving up.
    assert connect.call_count == 5
    opener.assert_not_called()


def test_wait_for_port_then_open_remaps_wildcard_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``0.0.0.0`` bind probes ``127.0.0.1`` — connect(0.0.0.0) is undefined."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr("agent_guardian.cli._stdout_is_tty", lambda: True)

    fake_conn = mock.MagicMock()
    fake_conn.__enter__ = mock.MagicMock(return_value=fake_conn)
    fake_conn.__exit__ = mock.MagicMock(return_value=False)

    with (
        mock.patch("socket.create_connection", return_value=fake_conn) as connect,
        mock.patch("webbrowser.open_new_tab") as opener,
    ):
        _wait_for_port_then_open("0.0.0.0", 7474, requested=True, path="/")

    connect.assert_called_once_with(("127.0.0.1", 7474), timeout=0.2)
    opener.assert_called_once_with("http://127.0.0.1:7474/")
