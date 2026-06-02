"""Auto-serve lifecycle: spawn a dashboard child for the duration of a scan.

QA-009. Default behaviour for ``agent-guardian scan``: probe 127.0.0.1:7474;
if free, spawn a child ``agent-guardian serve`` and keep it alive for a
grace period after the scan completes so the operator can click the URL
that was printed at scan start without ``ERR_CONNECTION_REFUSED``.

POSIX (macOS/Linux) is the v1 target; Windows is best-effort (uses
``CREATE_NEW_PROCESS_GROUP`` + ``CTRL_BREAK_EVENT`` but is not CI-tested).

The module exposes a small set of pure helpers plus the
:class:`AutoServeManager` context manager. The pure helpers (suppression
matrix, port probe, free-port search, readiness poll) are individually
testable; the manager wires them together and owns the child process
lifecycle (spawn, wait-ready, signal-cascade shutdown).

No third-party dependency is taken on for the probe path; the module
uses :mod:`urllib.request` so it has zero new imports beyond the stdlib.
"""

from __future__ import annotations

import atexit
import contextlib
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import types
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final
from urllib.error import URLError
from urllib.request import Request, urlopen

__all__ = [
    "AutoServeManager",
    "AutoServeResult",
    "find_free_port",
    "probe_is_our_serve",
    "should_auto_serve",
    "wait_until_ready",
]

_LOG = logging.getLogger(__name__)

# Default loopback host + preferred port. Frozen — matches the CLI's
# ``DEFAULT_DASHBOARD_URL`` (``http://127.0.0.1:7474``).
DEFAULT_HOST: Final[str] = "127.0.0.1"
DEFAULT_PORT: Final[int] = 7474
DEFAULT_FALLBACK_RANGE: Final[range] = range(7475, 7500)
DEFAULT_GRACE_SECONDS: Final[int] = 300
DEFAULT_READY_TIMEOUT: Final[float] = 5.0
DEFAULT_SHUTDOWN_WAIT: Final[float] = 3.0
DEFAULT_KILL_WAIT: Final[float] = 1.0
_PROBE_TIMEOUT: Final[float] = 0.5
_POLL_INTERVAL: Final[float] = 0.05
_GRACE_TICK_SECONDS: Final[float] = 0.25


# ---------------------------------------------------------------------------
# Public data class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AutoServeResult:
    """Outcome of an :meth:`AutoServeManager.__enter__` call.

    Attributes:
        base_url: The dashboard base URL the scan should publish, e.g.
            ``"http://127.0.0.1:7474"``. Always loopback. Always reflects
            the *actual* bound port (which may be 7475..7499 if 7474 was
            occupied by a stranger).
        port: Numeric port the dashboard is reachable on (7474..7499).
        spawned: ``True`` iff this manager spawned a child process.
            ``False`` when reusing an existing serve OR when suppressed.
        reused: ``True`` iff an existing AG serve was detected on the
            preferred port and reused (no spawn).
        suppression_reason: Human-readable reason auto-serve was
            suppressed (one of the suppression triggers from
            :func:`should_auto_serve`) — ``None`` when we actively
            spawned or reused.
    """

    base_url: str
    port: int
    spawned: bool
    reused: bool
    suppression_reason: str | None


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def should_auto_serve(
    *,
    no_serve: bool,
    no_tui: bool,
    debug_format: str,
    publish: bool,
    stdout: IO[str] | None = None,
    environ: dict[str, str] | None = None,
) -> str | None:
    """Return the suppression reason, or ``None`` if auto-serve should run.

    Pure function — no side effects, no I/O beyond ``stdout.isatty()``.
    The suppression triggers (LOCKED) are evaluated in priority order:

    1. ``--no-publish``                              (no URL → no point)
    2. ``--no-serve``                                (explicit opt-out)
    3. ``--no-tui``                                  (operator wants quiet)
    4. ``--debug-format json``                       (NDJSON must stay clean)
    5. stdout is not a TTY                           (piped to file / jq / less)
    6. ``$CI=true``                                  (CI runner)
    7. ``$AGENT_GUARDIAN_DISABLE_AUTO_SERVE=1``      (env-level kill switch)
    8. ``$AGENT_GUARDIAN_DASHBOARD_URL`` is set       (remote dashboard in use)

    Args:
        no_serve: Value of the ``--no-serve`` CLI flag.
        no_tui: Value of the ``--no-tui`` CLI flag.
        debug_format: Value of the ``--debug-format`` CLI flag (``"text"``
            or ``"json"``).
        publish: ``True`` when the URL will be emitted; ``False`` for
            ``--no-publish`` runs.
        stdout: Override stream for the TTY check; defaults to
            :data:`sys.stdout`.
        environ: Override mapping for env-var checks; defaults to
            :data:`os.environ`.

    Returns:
        ``None`` if auto-serve should run, else a short human-readable
        reason string (used in logging + :attr:`AutoServeResult.suppression_reason`).
    """
    env = environ if environ is not None else dict(os.environ)
    out = stdout if stdout is not None else sys.stdout

    if not publish:
        return "--no-publish"
    if no_serve:
        return "--no-serve"
    if no_tui:
        return "--no-tui"
    if (debug_format or "").lower().strip() == "json":
        return "--debug-format json"
    isatty = getattr(out, "isatty", None)
    if not (callable(isatty) and isatty()):
        return "stdout is not a TTY"
    ci = (env.get("CI") or "").strip().lower()
    if ci in ("1", "true", "yes", "on"):
        return "$CI"
    if (env.get("AGENT_GUARDIAN_DISABLE_AUTO_SERVE") or "").strip() == "1":
        return "$AGENT_GUARDIAN_DISABLE_AUTO_SERVE"
    dash_url = (env.get("AGENT_GUARDIAN_DASHBOARD_URL") or "").strip()
    if dash_url and dash_url != "http://127.0.0.1:7474":
        return "$AGENT_GUARDIAN_DASHBOARD_URL"
    return None


def probe_is_our_serve(
    host: str,
    port: int,
    *,
    timeout: float = _PROBE_TIMEOUT,
) -> bool:
    """Return ``True`` iff ``GET http://{host}:{port}/healthz`` returns the
    canonical AgentGuardian dashboard shape.

    Canonical shape: HTTP 200, JSON content-type, body has ``status ==
    "ok"`` AND a ``version`` key.

    Uses :mod:`urllib.request` (stdlib-only). Any exception (connection
    refused, timeout, bad JSON, missing key, wrong status) → ``False``.

    Args:
        host: Loopback host to probe (typically ``127.0.0.1``).
        port: Port to probe.
        timeout: Hard timeout in seconds for the probe request.
    """
    # Hardcoded ``http://{host}:{port}/healthz`` against the local dashboard
    # loopback; no user-controlled scheme or URL reaches ``urlopen``.
    url = f"http://{host}:{port}/healthz"
    req = Request(url, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:  # nosec B310 — hardcoded http loopback health probe
            if getattr(resp, "status", None) != 200:
                return False
            ctype = resp.headers.get("content-type", "")
            if "json" not in ctype.lower():
                return False
            raw = resp.read()
    except (URLError, TimeoutError, ConnectionError, OSError, ValueError):
        return False
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(body, dict):
        return False
    if body.get("status") != "ok":
        return False
    return "version" in body


def find_free_port(
    *,
    start: int = DEFAULT_FALLBACK_RANGE.start,
    end_exclusive: int = DEFAULT_FALLBACK_RANGE.stop,
    host: str = DEFAULT_HOST,
) -> int | None:
    """Bind-and-close port probe across ``[start, end_exclusive)``.

    Returns the first port that successfully bound, or ``None`` if every
    port in the range was occupied. Sets ``SO_REUSEADDR`` to avoid
    TIME_WAIT false positives.

    Args:
        start: Inclusive lower bound of the port search range.
        end_exclusive: Exclusive upper bound.
        host: Loopback interface to bind against.
    """
    for port in range(start, end_exclusive):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
        except OSError:
            continue
        else:
            return port
        finally:
            sock.close()
    return None


def wait_until_ready(
    port: int,
    *,
    host: str = DEFAULT_HOST,
    timeout: float = DEFAULT_READY_TIMEOUT,
    poll_interval: float = _POLL_INTERVAL,
) -> bool:
    """Poll ``GET /healthz`` until it returns the AG shape or timeout.

    Returns ``True`` on success, ``False`` on timeout. Uses
    :func:`probe_is_our_serve` internally for the response-shape check.

    Args:
        port: Port the dashboard is bound to.
        host: Loopback host.
        timeout: Max wall seconds to wait for readiness.
        poll_interval: Seconds between polls.
    """
    deadline = time.monotonic() + timeout
    while True:
        if probe_is_our_serve(host, port, timeout=min(0.5, max(poll_interval, 0.1))):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class AutoServeManager:
    """Spawn (or reuse) a dashboard child for the lifetime of a ``with`` block.

    Lifecycle (locked in DESIGN_LOCK §3)::

        INIT → DECIDE
             ├→ SUPPRESSED      (caller passed a suppression_reason)
             ├→ REUSE_EXISTING  (port 7474 is OUR serve)
             └→ SPAWN_NEW       (7474 free, OR 7474 occupied-by-stranger → 7475..7499)
        SCAN_RUNNING → GRACE_PERIOD → SHUTDOWN

    On ``__exit__`` (always — even on uncaught exceptions / SIGINT) the
    manager kills the spawned child via :func:`os.killpg` (POSIX) or
    :data:`signal.CTRL_BREAK_EVENT` (Windows) and restores the original
    signal handlers.

    Args:
        host: Loopback interface to bind / probe against.
        preferred_port: First port to try (default 7474).
        fallback_range: Range to scan if ``preferred_port`` is taken by
            something that is not our serve.
        grace_seconds: Seconds to keep the dashboard alive after the scan
            body returns. ``0`` shuts it down immediately, ``-1`` blocks
            until SIGINT/SIGTERM.
        token: Optional dashboard auth token; forwarded to the child via
            ``$AGENT_GUARDIAN_DASHBOARD_TOKEN``.
        suppression_reason: When set (typically by
            :func:`should_auto_serve`), the manager skips DECIDE entirely
            and surfaces a no-op :class:`AutoServeResult`.
        stderr_log_path: Where to redirect child stderr. Defaults to
            ``~/.agentguardian/auto_serve.log``.
        ready_timeout: Seconds to wait for ``/healthz`` to come up after
            spawn before degrading to SUPPRESSED.
        on_banner: Optional callback invoked once with the grace-period
            banner string. Defaults to :data:`sys.stdout.write`.
        environ: Override mapping for env vars (for tests).
        spawn_command: Optional spawn argv override; if omitted the
            manager runs ``[sys.executable, "-m", "agent_guardian",
            "serve", "--host", host, "--port", str(port)]``.
    """

    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        preferred_port: int = DEFAULT_PORT,
        fallback_range: range = DEFAULT_FALLBACK_RANGE,
        grace_seconds: int = DEFAULT_GRACE_SECONDS,
        token: str | None = None,
        suppression_reason: str | None = None,
        stderr_log_path: Path | None = None,
        ready_timeout: float = DEFAULT_READY_TIMEOUT,
        on_banner: Callable[[str], None] | None = None,
        environ: dict[str, str] | None = None,
        spawn_command: list[str] | None = None,
    ) -> None:
        self._host = host
        self._preferred_port = preferred_port
        self._fallback_range = fallback_range
        self._grace_seconds = grace_seconds
        self._token = token
        self._initial_suppression = suppression_reason
        self._stderr_log_path = (
            stderr_log_path
            if stderr_log_path is not None
            else Path.home() / ".agentguardian" / "auto_serve.log"
        )
        self._ready_timeout = ready_timeout
        self._on_banner = on_banner if on_banner is not None else sys.stdout.write
        self._environ = environ if environ is not None else dict(os.environ)
        self._spawn_command = spawn_command

        self._child: subprocess.Popen[bytes] | None = None
        self._stderr_handle: IO[bytes] | None = None
        self._result: AutoServeResult | None = None
        self._stop_event = threading.Event()
        self._prev_sigint: signal.Handlers | Callable[..., object] | None | int = None
        self._prev_sigterm: signal.Handlers | Callable[..., object] | None | int = None
        self._signal_handlers_installed = False
        self._grace_waited = False
        self._shutdown_done = False
        self._atexit_registered = False

    # ------------------------------------------------------------------
    # Context-manager API
    # ------------------------------------------------------------------

    def __enter__(self) -> AutoServeResult:
        if self._initial_suppression is not None:
            self._result = AutoServeResult(
                base_url=f"http://{self._host}:{self._preferred_port}",
                port=self._preferred_port,
                spawned=False,
                reused=False,
                suppression_reason=self._initial_suppression,
            )
            return self._result

        port, spawned, reused = self._decide()
        self._result = AutoServeResult(
            base_url=f"http://{self._host}:{port}",
            port=port,
            spawned=spawned,
            reused=reused,
            suppression_reason=None
            if (spawned or reused)
            else "spawn failed: dashboard did not become ready",
        )
        return self._result

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        self._shutdown_child()
        self._restore_signal_handlers()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def grace_wait(self) -> None:
        """Block for ``grace_seconds`` (or forever if ``-1``, or instantly if ``0``).

        Prints a single-line banner at entry (via the ``on_banner``
        callback). Interruptible by SIGINT / SIGTERM → returns early.
        Idempotent: calling more than once is a no-op after the first.
        """
        if self._grace_waited:
            return
        self._grace_waited = True

        result = self._result
        if result is None or not result.spawned:
            return
        if self._grace_seconds == 0:
            return

        url = result.base_url
        if self._grace_seconds < 0:
            self._on_banner(f"▸ Dashboard staying up at {url} — Ctrl-C to exit\n")
        else:
            minutes = self._grace_seconds / 60.0
            self._on_banner(
                f"▸ Dashboard staying up at {url} for "
                f"{_format_grace_window(self._grace_seconds, minutes)} — "
                f"Ctrl-C to exit\n"
            )
        _flush_stdout()

        remaining = float(self._grace_seconds)
        while not self._stop_event.is_set():
            self._stop_event.wait(_GRACE_TICK_SECONDS)
            if self._stop_event.is_set():
                break
            if self._grace_seconds < 0:
                continue
            remaining -= _GRACE_TICK_SECONDS
            if remaining <= 0:
                break

        self._on_banner(f"▸ Dashboard shut down at {url}\n")
        _flush_stdout()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _decide(self) -> tuple[int, bool, bool]:
        """Run the DECIDE state. Returns ``(port, spawned, reused)``."""
        if probe_is_our_serve(self._host, self._preferred_port):
            _LOG.debug(
                "auto_serve: existing AG serve detected on %s:%d — reusing",
                self._host,
                self._preferred_port,
            )
            return (self._preferred_port, False, True)

        target_port = self._preferred_port
        if _port_is_in_use(self._host, self._preferred_port):
            free = find_free_port(
                start=self._fallback_range.start,
                end_exclusive=self._fallback_range.stop,
                host=self._host,
            )
            if free is None:
                _LOG.warning(
                    "auto_serve: every port in %s..%s occupied — suppressing",
                    self._fallback_range.start,
                    self._fallback_range.stop - 1,
                )
                return (self._preferred_port, False, False)
            target_port = free

        try:
            self._install_signal_handlers()
            self._child = self._spawn(target_port)
        except OSError as exc:
            _LOG.warning("auto_serve: spawn failed (%s) — suppressing", exc)
            self._restore_signal_handlers()
            return (target_port, False, False)

        if not wait_until_ready(
            target_port,
            host=self._host,
            timeout=self._ready_timeout,
        ):
            _LOG.warning(
                "auto_serve: dashboard on %s:%d did not become ready within %.1fs — suppressing",
                self._host,
                target_port,
                self._ready_timeout,
            )
            self._shutdown_child()
            self._restore_signal_handlers()
            return (target_port, False, False)

        if not self._atexit_registered:
            atexit.register(self._shutdown_child)
            self._atexit_registered = True
        return (target_port, True, False)

    def _spawn(self, port: int) -> subprocess.Popen[bytes]:
        """Spawn the child ``agent-guardian serve`` process."""
        argv = self._spawn_command or [
            sys.executable,
            "-m",
            "agent_guardian",
            "serve",
            "--host",
            self._host,
            "--port",
            str(port),
        ]
        env = dict(self._environ)
        if self._token is not None:
            env["AGENT_GUARDIAN_DASHBOARD_TOKEN"] = self._token

        log_path = self._stderr_log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._stderr_handle = log_path.open("ab")

        creationflags = 0
        if sys.platform == "win32":  # pragma: no cover - non-POSIX
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        return subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr_handle,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            creationflags=creationflags,
        )

    def _install_signal_handlers(self) -> None:
        if self._signal_handlers_installed:
            return
        if threading.current_thread() is not threading.main_thread():
            # Signal handlers can only be installed from the main thread.
            # If we're not on it (e.g. running inside a test worker), the
            # caller's process-level SIGINT path still tears us down via
            # __exit__; we simply skip the handler install.
            return

        def _handler(_signum: int, _frame: types.FrameType | None) -> None:
            self._stop_event.set()

        try:
            self._prev_sigint = signal.signal(signal.SIGINT, _handler)
        except (ValueError, OSError):  # pragma: no cover - non-main-thread guard
            self._prev_sigint = None
        try:
            self._prev_sigterm = signal.signal(signal.SIGTERM, _handler)
        except (ValueError, OSError):  # pragma: no cover - non-main-thread guard
            self._prev_sigterm = None
        self._signal_handlers_installed = True

    def _restore_signal_handlers(self) -> None:
        if not self._signal_handlers_installed:
            return
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            if self._prev_sigint is not None:
                signal.signal(signal.SIGINT, self._prev_sigint)
            if self._prev_sigterm is not None:
                signal.signal(signal.SIGTERM, self._prev_sigterm)
        except (ValueError, OSError):  # pragma: no cover - non-main-thread guard
            # signal.signal() rejects calls off the main thread and may raise
            # OSError if the previous handler was a C-level callable Python
            # can't restore. Either way we can't put the handler back — log
            # for posterity and move on so cleanup keeps unwinding.
            _LOG.debug("auto_serve: could not restore prior signal handlers", exc_info=True)
        self._signal_handlers_installed = False

    def _shutdown_child(self) -> None:
        if self._shutdown_done:
            return
        self._shutdown_done = True

        child = self._child
        if child is None:
            self._close_stderr_log()
            return

        if child.poll() is not None:
            self._close_stderr_log()
            self._child = None
            return

        try:
            if sys.platform == "win32":  # pragma: no cover - non-POSIX
                ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM)
                child.send_signal(ctrl_break)
            else:
                try:
                    pgid = os.getpgid(child.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    child.terminate()
        except OSError:
            # The child may have already exited between poll() and signal
            # delivery, or the OS may have reaped its pgid. Either case is
            # benign — wait() below will confirm. Log for diagnostics.
            _LOG.debug(
                "auto_serve: SIGTERM delivery to child pid=%d failed",
                child.pid,
                exc_info=True,
            )

        try:
            child.wait(timeout=DEFAULT_SHUTDOWN_WAIT)
        except subprocess.TimeoutExpired:
            try:
                if sys.platform == "win32":  # pragma: no cover - non-POSIX
                    child.kill()
                else:
                    try:
                        pgid = os.getpgid(child.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        child.kill()
            except OSError:
                # SIGKILL escalation failed (child likely already reaped, or
                # pgid no longer exists). Harmless — wait() below confirms.
                _LOG.debug(
                    "auto_serve: SIGKILL escalation to child pid=%d failed",
                    child.pid,
                    exc_info=True,
                )
            try:
                child.wait(timeout=DEFAULT_KILL_WAIT)
            except subprocess.TimeoutExpired:
                _LOG.warning(
                    "auto_serve: child pid=%d did not exit after SIGKILL",
                    child.pid,
                )

        self._close_stderr_log()
        self._child = None

    def _close_stderr_log(self) -> None:
        handle = self._stderr_handle
        if handle is None:
            return
        with contextlib.suppress(OSError):
            handle.close()
        self._stderr_handle = None


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _port_is_in_use(host: str, port: int) -> bool:
    """Return ``True`` iff ``host:port`` cannot currently be bound.

    Uses a bind-and-close probe (more robust than ``connect_ex`` against
    squatters with small listen backlogs: a squatter that hasn't called
    ``accept`` will refuse a connect once its queue fills). Sets
    ``SO_REUSEADDR`` so a recently-released port in TIME_WAIT is still
    reported correctly. Any unexpected error → conservatively ``True``
    (assume in use) so we fall back rather than collide.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError:
        return True
    finally:
        sock.close()
    return False


def _format_grace_window(seconds: int, minutes: float) -> str:
    if seconds % 60 == 0 and seconds >= 60:
        whole = seconds // 60
        return f"{whole} min"
    if seconds >= 60:
        return f"{minutes:.1f} min"
    return f"{seconds}s"


def _flush_stdout() -> None:
    flush = getattr(sys.stdout, "flush", None)
    if callable(flush):
        with contextlib.suppress(OSError, ValueError):
            flush()
