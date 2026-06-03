"""Unit tests for :mod:`agent_guardian.ui.auto_serve` (QA-009).

Pure-function suite — no real subprocesses are spawned here. Integration
coverage lives in ``test_auto_serve_lifecycle.py``.
"""

from __future__ import annotations

import io
import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, ClassVar

import pytest

from agent_guardian.ui.auto_serve import (
    AutoServeManager,
    AutoServeResult,
    find_free_port,
    probe_is_our_serve,
    should_auto_serve,
    wait_until_ready,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeTty(io.StringIO):
    """An ``io.StringIO`` that reports as a TTY for :func:`should_auto_serve`."""

    def __init__(self, tty: bool = True) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class _HealthHandler(BaseHTTPRequestHandler):
    """Tiny stdlib HTTP server impersonating AgentGuardian's ``/healthz``."""

    SHAPE: ClassVar[dict[str, Any]] = {"status": "ok", "version": "0.0.0-test"}

    def log_message(self, format: str, *args: Any) -> None:
        # Silence the default access log so pytest stdout stays clean.
        return

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"nope")
            return
        body = json.dumps(self.SHAPE).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _WrongShapeHandler(_HealthHandler):
    SHAPE: ClassVar[dict[str, Any]] = {"status": "ok"}  # missing "version" key


class _DegradedHandler(_HealthHandler):
    SHAPE: ClassVar[dict[str, Any]] = {
        "status": "degraded",
        "version": "0.0.0-test",
    }


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


@pytest.fixture
def healthz_server() -> Iterator[int]:
    server, port = _start_server(_HealthHandler)
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def wrong_shape_server() -> Iterator[int]:
    server, port = _start_server(_WrongShapeHandler)
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def degraded_server() -> Iterator[int]:
    server, port = _start_server(_DegradedHandler)
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


def _closed_port() -> int:
    """Return a port that nothing is listening on."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# should_auto_serve — the suppression matrix
# ---------------------------------------------------------------------------


def _kwargs(**overrides: Any) -> dict[str, Any]:
    """Build a default-happy ``should_auto_serve`` kwargs bundle."""
    base: dict[str, Any] = {
        "no_serve": False,
        "no_tui": False,
        "debug_format": "text",
        "publish": True,
        "stdout": _FakeTty(tty=True),
        "environ": {},
    }
    base.update(overrides)
    return base


def test_should_auto_serve_default_returns_none() -> None:
    assert should_auto_serve(**_kwargs()) is None


def test_should_auto_serve_no_publish_wins() -> None:
    assert should_auto_serve(**_kwargs(publish=False)) == "--no-publish"


def test_should_auto_serve_no_serve_flag() -> None:
    assert should_auto_serve(**_kwargs(no_serve=True)) == "--no-serve"


def test_should_auto_serve_no_tui_flag() -> None:
    assert should_auto_serve(**_kwargs(no_tui=True)) == "--no-tui"


def test_should_auto_serve_debug_format_json() -> None:
    assert should_auto_serve(**_kwargs(debug_format="json")) == "--debug-format json"


def test_should_auto_serve_debug_format_case_insensitive() -> None:
    assert should_auto_serve(**_kwargs(debug_format="JSON")) == "--debug-format json"


def test_should_auto_serve_non_tty_stdout() -> None:
    pipe = _FakeTty(tty=False)
    assert should_auto_serve(**_kwargs(stdout=pipe)) == "stdout is not a TTY"


def test_should_auto_serve_stdout_without_isatty() -> None:
    class _NoIsatty:
        pass

    assert should_auto_serve(**_kwargs(stdout=_NoIsatty())) == "stdout is not a TTY"


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on", "True"])
def test_should_auto_serve_ci_truthy(value: str) -> None:
    env = {"CI": value}
    assert should_auto_serve(**_kwargs(environ=env)) == "$CI"


def test_should_auto_serve_ci_falsy_runs() -> None:
    env = {"CI": "false"}
    assert should_auto_serve(**_kwargs(environ=env)) is None


def test_should_auto_serve_disable_env() -> None:
    env = {"AGENT_GUARDIAN_DISABLE_AUTO_SERVE": "1"}
    assert should_auto_serve(**_kwargs(environ=env)) == "$AGENT_GUARDIAN_DISABLE_AUTO_SERVE"


def test_should_auto_serve_disable_env_non_one_runs() -> None:
    env = {"AGENT_GUARDIAN_DISABLE_AUTO_SERVE": "0"}
    assert should_auto_serve(**_kwargs(environ=env)) is None


def test_should_auto_serve_remote_dashboard_url() -> None:
    env = {"AGENT_GUARDIAN_DASHBOARD_URL": "https://dash.example.com"}
    assert should_auto_serve(**_kwargs(environ=env)) == "$AGENT_GUARDIAN_DASHBOARD_URL"


def test_should_auto_serve_default_dashboard_url_does_not_suppress() -> None:
    env = {"AGENT_GUARDIAN_DASHBOARD_URL": "http://127.0.0.1:7474"}
    assert should_auto_serve(**_kwargs(environ=env)) is None


def test_should_auto_serve_blank_dashboard_url_does_not_suppress() -> None:
    env = {"AGENT_GUARDIAN_DASHBOARD_URL": "   "}
    assert should_auto_serve(**_kwargs(environ=env)) is None


# ---------------------------------------------------------------------------
# probe_is_our_serve
# ---------------------------------------------------------------------------


def test_probe_is_our_serve_happy_path(healthz_server: int) -> None:
    assert probe_is_our_serve("127.0.0.1", healthz_server) is True


def test_probe_is_our_serve_missing_version_key(wrong_shape_server: int) -> None:
    assert probe_is_our_serve("127.0.0.1", wrong_shape_server) is False


def test_probe_is_our_serve_degraded_status(degraded_server: int) -> None:
    assert probe_is_our_serve("127.0.0.1", degraded_server) is False


def test_probe_is_our_serve_connection_refused() -> None:
    port = _closed_port()
    assert probe_is_our_serve("127.0.0.1", port, timeout=0.2) is False


def test_probe_is_our_serve_non_json_content_type() -> None:
    class _PlainTextHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","version":"0"}')

    server, port = _start_server(_PlainTextHandler)
    try:
        assert probe_is_our_serve("127.0.0.1", port) is False
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# find_free_port
# ---------------------------------------------------------------------------


def test_find_free_port_returns_first_free_in_range() -> None:
    bound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bound.bind(("127.0.0.1", 0))
    occupied = int(bound.getsockname()[1])
    bound.listen(1)
    try:
        # Search a 3-port window: [occupied, occupied+3). occupied is
        # taken, so we expect occupied+1 (or occupied+2).
        result = find_free_port(
            start=occupied,
            end_exclusive=occupied + 3,
            host="127.0.0.1",
        )
        assert result is not None
        assert result != occupied
        assert occupied < result < occupied + 3
    finally:
        bound.close()


def test_find_free_port_returns_none_when_exhausted() -> None:
    sockets: list[socket.socket] = []
    base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    base_socket.bind(("127.0.0.1", 0))
    start = int(base_socket.getsockname()[1])
    sockets.append(base_socket)
    base_socket.listen(1)

    # Bind every port in [start, start+3) so the search exhausts.
    extra_ports: list[int] = []
    for offset in (1, 2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", start + offset))
        except OSError:
            sock.close()
            pytest.skip("unable to bind a contiguous trio of ports")
        sock.listen(1)
        sockets.append(sock)
        extra_ports.append(start + offset)

    try:
        result = find_free_port(
            start=start,
            end_exclusive=start + 3,
            host="127.0.0.1",
        )
        assert result is None
    finally:
        for sock in sockets:
            sock.close()


def test_find_free_port_skips_to_next_when_first_busy() -> None:
    bound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bound.bind(("127.0.0.1", 0))
    occupied = int(bound.getsockname()[1])
    bound.listen(1)
    try:
        result = find_free_port(
            start=occupied,
            end_exclusive=occupied + 50,
            host="127.0.0.1",
        )
        assert result is not None
        assert result != occupied
    finally:
        bound.close()


# ---------------------------------------------------------------------------
# wait_until_ready
# ---------------------------------------------------------------------------


def test_wait_until_ready_succeeds_on_first_poll(healthz_server: int) -> None:
    assert wait_until_ready(healthz_server, timeout=1.0) is True


def test_wait_until_ready_times_out_on_closed_port() -> None:
    port = _closed_port()
    assert wait_until_ready(port, timeout=0.4, poll_interval=0.05) is False


# ---------------------------------------------------------------------------
# AutoServeManager — DECIDE branches without a real spawn
# ---------------------------------------------------------------------------


def test_manager_suppressed_returns_no_spawn() -> None:
    mgr = AutoServeManager(suppression_reason="--no-serve")
    with mgr as result:
        assert isinstance(result, AutoServeResult)
        assert result.spawned is False
        assert result.reused is False
        assert result.suppression_reason == "--no-serve"
        assert result.base_url == "http://127.0.0.1:7474"


def test_manager_reuses_existing_serve_on_preferred_port(
    healthz_server: int,
) -> None:
    mgr = AutoServeManager(preferred_port=healthz_server)
    with mgr as result:
        assert result.reused is True
        assert result.spawned is False
        assert result.suppression_reason is None
        assert result.port == healthz_server
        assert result.base_url == f"http://127.0.0.1:{healthz_server}"


def test_manager_spawns_when_no_existing_serve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Spawn path with a stubbed Popen — we never run a real serve here."""

    class _FakePopen:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.pid = 99999
            self._polled = False

        def poll(self) -> int | None:
            return None if not self._polled else 0

        def wait(self, timeout: float | None = None) -> int:
            self._polled = True
            return 0

        def send_signal(self, sig: int) -> None:
            self._polled = True

        def terminate(self) -> None:
            self._polled = True

        def kill(self) -> None:
            self._polled = True

    from agent_guardian.ui import auto_serve as auto_serve_mod

    # Pretend port 7474 is free AND no existing serve responds.
    monkeypatch.setattr(auto_serve_mod, "_port_is_in_use", lambda host, port: False)
    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: False)
    # Wait-until-ready returns True so the manager proceeds to the
    # "spawned & healthy" branch without actually polling the network.
    monkeypatch.setattr(auto_serve_mod, "wait_until_ready", lambda *a, **kw: True)
    monkeypatch.setattr(auto_serve_mod.subprocess, "Popen", _FakePopen)

    log_path = tmp_path / "auto_serve.log"
    mgr = AutoServeManager(
        stderr_log_path=log_path,
        grace_seconds=0,
    )
    with mgr as result:
        assert result.spawned is True
        assert result.reused is False
        assert result.suppression_reason is None
        assert result.port == 7474


def test_manager_falls_back_when_preferred_port_is_foreign(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Foreign server on 7474 → DECIDE picks a port from the fallback range."""

    class _FakePopen:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.pid = 88888
            self._polled = False

        def poll(self) -> int | None:
            return None if not self._polled else 0

        def wait(self, timeout: float | None = None) -> int:
            self._polled = True
            return 0

        def send_signal(self, sig: int) -> None:
            self._polled = True

        def terminate(self) -> None:
            self._polled = True

        def kill(self) -> None:
            self._polled = True

    from agent_guardian.ui import auto_serve as auto_serve_mod

    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: False)
    monkeypatch.setattr(auto_serve_mod, "_port_is_in_use", lambda host, port: True)
    monkeypatch.setattr(auto_serve_mod, "find_free_port", lambda **kw: 7480)
    monkeypatch.setattr(auto_serve_mod, "wait_until_ready", lambda *a, **kw: True)
    monkeypatch.setattr(auto_serve_mod.subprocess, "Popen", _FakePopen)

    mgr = AutoServeManager(
        stderr_log_path=tmp_path / "auto_serve.log",
        grace_seconds=0,
    )
    with mgr as result:
        assert result.spawned is True
        assert result.port == 7480
        assert result.base_url == "http://127.0.0.1:7480"


def test_manager_degrades_when_spawn_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Popen raising OSError → DEGRADE to a no-spawn result with reason set."""
    from agent_guardian.ui import auto_serve as auto_serve_mod

    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: False)
    monkeypatch.setattr(auto_serve_mod, "_port_is_in_use", lambda host, port: False)

    def _broken_popen(*args: Any, **kwargs: Any) -> Any:
        raise OSError("no resources")

    monkeypatch.setattr(auto_serve_mod.subprocess, "Popen", _broken_popen)

    mgr = AutoServeManager(
        stderr_log_path=tmp_path / "auto_serve.log",
        grace_seconds=0,
    )
    with mgr as result:
        assert result.spawned is False
        assert result.reused is False
        assert result.suppression_reason is not None
        assert "spawn failed" in result.suppression_reason


def test_manager_degrades_when_ready_probe_times_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """Spawn succeeds, but /healthz never comes up → DEGRADE."""

    class _FakePopen:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.pid = 77777
            self._polled = False

        def poll(self) -> int | None:
            return None if not self._polled else 0

        def wait(self, timeout: float | None = None) -> int:
            self._polled = True
            return 0

        def send_signal(self, sig: int) -> None:
            self._polled = True

        def terminate(self) -> None:
            self._polled = True

        def kill(self) -> None:
            self._polled = True

    from agent_guardian.ui import auto_serve as auto_serve_mod

    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: False)
    monkeypatch.setattr(auto_serve_mod, "_port_is_in_use", lambda host, port: False)
    monkeypatch.setattr(auto_serve_mod, "wait_until_ready", lambda *a, **kw: False)
    monkeypatch.setattr(auto_serve_mod.subprocess, "Popen", _FakePopen)

    mgr = AutoServeManager(
        stderr_log_path=tmp_path / "auto_serve.log",
        grace_seconds=0,
        ready_timeout=0.1,
    )
    with mgr as result:
        assert result.spawned is False
        assert result.suppression_reason is not None
        assert "spawn failed" in result.suppression_reason


# ---------------------------------------------------------------------------
# grace_wait — banner, idempotency, zero/negative semantics
# ---------------------------------------------------------------------------


def test_grace_wait_zero_returns_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """grace=0 → no banner, instant return."""

    class _FakePopen:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.pid = 11111

        def poll(self) -> int | None:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def send_signal(self, sig: int) -> None:
            pass

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            pass

    from agent_guardian.ui import auto_serve as auto_serve_mod

    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: False)
    monkeypatch.setattr(auto_serve_mod, "_port_is_in_use", lambda host, port: False)
    monkeypatch.setattr(auto_serve_mod, "wait_until_ready", lambda *a, **kw: True)
    monkeypatch.setattr(auto_serve_mod.subprocess, "Popen", _FakePopen)

    banner_calls: list[str] = []
    mgr = AutoServeManager(
        grace_seconds=0,
        on_banner=banner_calls.append,
    )
    with mgr:
        mgr.grace_wait()
    assert banner_calls == []


def test_grace_wait_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = AutoServeManager(suppression_reason="--no-serve", grace_seconds=0)
    with mgr:
        mgr.grace_wait()
        # Second call must be a no-op.
        mgr.grace_wait()


def test_grace_wait_no_spawn_no_banner() -> None:
    """When suppressed (no spawn), grace_wait must not print a banner."""
    banner_calls: list[str] = []
    mgr = AutoServeManager(
        suppression_reason="--no-serve",
        grace_seconds=300,
        on_banner=banner_calls.append,
    )
    with mgr:
        mgr.grace_wait()
    assert banner_calls == []


# ---------------------------------------------------------------------------
# AutoServeResult — surface dataclass guarantees
# ---------------------------------------------------------------------------


def test_auto_serve_result_is_frozen() -> None:
    result = AutoServeResult(
        base_url="http://127.0.0.1:7474",
        port=7474,
        spawned=True,
        reused=False,
        suppression_reason=None,
    )
    with pytest.raises((AttributeError, TypeError)):
        # frozen=True → mutation must raise
        result.port = 9999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Probe edge cases — non-200, non-JSON body, weird shapes
# ---------------------------------------------------------------------------


def test_probe_is_our_serve_returns_500() -> None:
    class _500Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","version":"1"}')

    server, port = _start_server(_500Handler)
    try:
        assert probe_is_our_serve("127.0.0.1", port) is False
    finally:
        server.shutdown()
        server.server_close()


def test_probe_is_our_serve_returns_non_dict() -> None:
    class _ListHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'["status","ok"]')

    server, port = _start_server(_ListHandler)
    try:
        assert probe_is_our_serve("127.0.0.1", port) is False
    finally:
        server.shutdown()
        server.server_close()


def test_probe_is_our_serve_malformed_json() -> None:
    class _BrokenHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{not json}")

    server, port = _start_server(_BrokenHandler)
    try:
        assert probe_is_our_serve("127.0.0.1", port) is False
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Grace-window formatting + flush helper
# ---------------------------------------------------------------------------


def test_format_grace_window_minutes_whole() -> None:
    from agent_guardian.ui.auto_serve import _format_grace_window

    assert _format_grace_window(60, 1.0) == "1 min"
    assert _format_grace_window(300, 5.0) == "5 min"


def test_format_grace_window_minutes_partial() -> None:
    from agent_guardian.ui.auto_serve import _format_grace_window

    assert _format_grace_window(90, 1.5) == "1.5 min"


def test_format_grace_window_seconds() -> None:
    from agent_guardian.ui.auto_serve import _format_grace_window

    assert _format_grace_window(45, 0.75) == "45s"


def test_flush_stdout_survives_broken_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_guardian.ui import auto_serve as mod

    class _Broken:
        def flush(self) -> None:
            raise OSError("pipe broken")

    monkeypatch.setattr(mod.sys, "stdout", _Broken())
    # Must not raise.
    mod._flush_stdout()


def test_flush_stdout_no_flush_attr(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_guardian.ui import auto_serve as mod

    class _Noisy:
        pass

    monkeypatch.setattr(mod.sys, "stdout", _Noisy())
    # No flush attribute → silently no-op.
    mod._flush_stdout()


# ---------------------------------------------------------------------------
# _port_is_in_use — direct exercise
# ---------------------------------------------------------------------------


def test_port_is_in_use_true_when_squatter_listening() -> None:
    from agent_guardian.ui.auto_serve import _port_is_in_use

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.listen(1)
    try:
        assert _port_is_in_use("127.0.0.1", port) is True
    finally:
        sock.close()


def test_port_is_in_use_false_for_free_port() -> None:
    from agent_guardian.ui.auto_serve import _port_is_in_use

    port = _closed_port()
    assert _port_is_in_use("127.0.0.1", port) is False


# ---------------------------------------------------------------------------
# DECIDE — fallback exhausted → degrade (find_free_port returns None)
# ---------------------------------------------------------------------------


def test_manager_degrades_when_fallback_exhausted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from agent_guardian.ui import auto_serve as auto_serve_mod

    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: False)
    monkeypatch.setattr(auto_serve_mod, "_port_is_in_use", lambda host, port: True)
    monkeypatch.setattr(auto_serve_mod, "find_free_port", lambda **kw: None)

    mgr = AutoServeManager(
        stderr_log_path=tmp_path / "auto_serve.log",
        grace_seconds=0,
    )
    with mgr as result:
        assert result.spawned is False
        assert result.reused is False
        assert result.suppression_reason is not None


# ---------------------------------------------------------------------------
# grace_wait — negative grace seconds use the "until Ctrl-C" banner
# ---------------------------------------------------------------------------


def test_grace_wait_negative_emits_until_ctrl_c_banner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """grace=-1 → banner reads 'until Ctrl-C', sleep loop is interruptible."""
    from agent_guardian.ui import auto_serve as auto_serve_mod

    class _FakePopen:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.pid = 33333

        def poll(self) -> int | None:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def send_signal(self, sig: int) -> None:
            pass

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            pass

    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: False)
    monkeypatch.setattr(auto_serve_mod, "_port_is_in_use", lambda host, port: False)
    monkeypatch.setattr(auto_serve_mod, "wait_until_ready", lambda *a, **kw: True)
    monkeypatch.setattr(auto_serve_mod.subprocess, "Popen", _FakePopen)

    banners: list[str] = []
    mgr = AutoServeManager(
        grace_seconds=-1,
        stderr_log_path=tmp_path / "auto_serve.log",
        on_banner=banners.append,
    )
    with mgr:
        # Set stop event so the loop terminates promptly.
        mgr._stop_event.set()
        mgr.grace_wait()

    # Banner one should be the "Ctrl-C to exit" form.
    assert banners
    assert any("Ctrl-C to exit" in b for b in banners)


# ---------------------------------------------------------------------------
# DECIDE — reused branch via probe returning True
# ---------------------------------------------------------------------------


def test_manager_reuse_via_probe_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_guardian.ui import auto_serve as auto_serve_mod

    monkeypatch.setattr(auto_serve_mod, "probe_is_our_serve", lambda *a, **kw: True)
    mgr = AutoServeManager(preferred_port=7474, grace_seconds=0)
    with mgr as result:
        assert result.reused is True
        assert result.spawned is False
        assert result.port == 7474
