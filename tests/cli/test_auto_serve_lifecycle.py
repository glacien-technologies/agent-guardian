"""Lifecycle integration tests for :mod:`agent_guardian.ui.auto_serve` (QA-009).

These tests spawn real ``python -m agent_guardian serve`` child processes
in order to validate the spawn-/-reuse-/-grace-/-shutdown lifecycle on
POSIX systems. Each child is bound to an ephemeral free port so the suite
is safe to run in parallel and does not collide with a developer's own
``agent-guardian serve`` instance on 7474.

Windows is best-effort: the file is skipped wholesale on win32 because
``os.killpg`` and ``signal.SIGINT`` semantics differ; the unit-test
matrix in ``test_auto_serve.py`` already exercises the cross-platform
branching points.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

from agent_guardian.ui.auto_serve import (
    AutoServeManager,
    probe_is_our_serve,
    wait_until_ready,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only lifecycle test (uses os.killpg + SIGINT semantics).",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _wait_child_exit(child: subprocess.Popen[bytes], timeout: float) -> bool:
    """Poll ``child.poll()`` until the child has exited or ``timeout`` expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            return True
        time.sleep(0.05)
    return child.poll() is not None


def _spawn_serve(port: int, *, log_path: Path) -> subprocess.Popen[bytes]:
    """Spawn ``agent-guardian serve`` directly for tests that need a pre-existing serve."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("ab")
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agent_guardian",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=log,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def _terminate_pg(child: subprocess.Popen[bytes]) -> None:
    try:
        pgid = os.getpgid(child.pid)
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        child.terminate()
    try:
        child.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        try:
            pgid = os.getpgid(child.pid)
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            child.kill()
        child.wait(timeout=2.0)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stderr_log(tmp_path: Path) -> Path:
    return tmp_path / "auto_serve.log"


@pytest.fixture
def free_port() -> int:
    return _free_port()


@pytest.fixture
def manual_serve(stderr_log: Path) -> Iterator[tuple[subprocess.Popen[bytes], int]]:
    """A real ``agent-guardian serve`` running on an ephemeral port."""
    port = _free_port()
    child = _spawn_serve(port, log_path=stderr_log)
    try:
        if not wait_until_ready(port, timeout=15.0):
            _terminate_pg(child)
            pytest.skip(f"manual serve on {port} never came up — uvicorn may not be installed")
        yield child, port
    finally:
        if child.poll() is None:
            _terminate_pg(child)


# ---------------------------------------------------------------------------
# L1 — Cold start: spawn binds quickly on a clean port
# ---------------------------------------------------------------------------


def test_cold_start_spawns_and_reaches_ready(free_port: int, stderr_log: Path) -> None:
    """A fresh AutoServeManager spawns a real child and the URL responds."""
    mgr = AutoServeManager(
        preferred_port=free_port,
        grace_seconds=0,
        stderr_log_path=stderr_log,
        ready_timeout=15.0,
    )
    t0 = time.monotonic()
    with mgr as result:
        elapsed_to_ready = time.monotonic() - t0
        assert result.spawned is True
        assert result.reused is False
        assert result.port == free_port
        assert result.base_url == f"http://127.0.0.1:{free_port}"
        # Sanity check the URL is actually reachable.
        with urlopen(f"{result.base_url}/healthz", timeout=2.0) as resp:
            assert resp.status == 200

    # The cold start should be well under 15s on any sensible dev box.
    assert elapsed_to_ready < 15.0


# ---------------------------------------------------------------------------
# L2 — Port reuse: existing AG serve on preferred port is detected + reused
# ---------------------------------------------------------------------------


def test_reuse_detects_existing_serve_no_second_spawn(
    manual_serve: tuple[subprocess.Popen[bytes], int],
    stderr_log: Path,
) -> None:
    pre_existing, port = manual_serve

    mgr = AutoServeManager(
        preferred_port=port,
        grace_seconds=0,
        stderr_log_path=stderr_log,
        reuse_existing=True,  # reuse is opt-in now (default: own dashboard per scan)
    )
    with mgr as result:
        assert result.reused is True
        assert result.spawned is False
        assert result.suppression_reason is None
        assert result.port == port

    # The pre-existing process must still be alive — we never killed it.
    assert pre_existing.poll() is None
    # And the URL must still be reachable post-__exit__.
    with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2.0) as resp:
        assert resp.status == 200


# ---------------------------------------------------------------------------
# L3 — Port collision: foreign server on preferred port → fallback range
# ---------------------------------------------------------------------------


def test_foreign_server_on_preferred_port_falls_back(
    stderr_log: Path,
) -> None:
    """A non-AG socket on the preferred port → DECIDE picks a fallback port."""
    preferred = _free_port()
    fallback_start = _free_port()
    fallback_end = fallback_start + 5

    # Squat the preferred port with a raw listening socket so
    # probe_is_our_serve returns False and the manager's port-in-use
    # check returns True.
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    squatter.bind(("127.0.0.1", preferred))
    squatter.listen(1)

    try:
        mgr = AutoServeManager(
            preferred_port=preferred,
            fallback_range=range(fallback_start, fallback_end),
            grace_seconds=0,
            stderr_log_path=stderr_log,
            ready_timeout=15.0,
        )
        with mgr as result:
            assert result.spawned is True
            assert result.reused is False
            assert result.port != preferred
            assert fallback_start <= result.port < fallback_end
            with urlopen(f"{result.base_url}/healthz", timeout=2.0) as resp:
                assert resp.status == 200
    finally:
        squatter.close()


# ---------------------------------------------------------------------------
# L4 — Shutdown: __exit__ kills the spawned child within a few seconds
# ---------------------------------------------------------------------------


def test_exit_kills_spawned_child(free_port: int, stderr_log: Path) -> None:
    mgr = AutoServeManager(
        preferred_port=free_port,
        grace_seconds=0,
        stderr_log_path=stderr_log,
        ready_timeout=15.0,
    )
    child_pid: int | None = None
    child_handle: subprocess.Popen[bytes] | None = None
    with mgr as result:
        assert result.spawned is True
        # Pull the spawned child handle through the (private) accessor —
        # tests of the lifecycle need to observe it. We assert on PID
        # existence rather than reach into more internals.
        child_handle = mgr._child
        assert child_handle is not None
        child_pid = child_handle.pid
        assert child_pid > 0

    assert child_handle is not None
    assert _wait_child_exit(child_handle, timeout=5.0), (
        "spawned dashboard child did not exit after __exit__"
    )


# ---------------------------------------------------------------------------
# L5 — Grace period: grace_wait blocks for ~N seconds then returns
# ---------------------------------------------------------------------------


def test_grace_wait_blocks_for_specified_seconds(free_port: int, stderr_log: Path) -> None:
    grace = 1
    mgr = AutoServeManager(
        preferred_port=free_port,
        grace_seconds=grace,
        stderr_log_path=stderr_log,
        ready_timeout=15.0,
        on_banner=lambda s: None,
    )
    with mgr:
        t0 = time.monotonic()
        mgr.grace_wait()
        elapsed = time.monotonic() - t0
    # Grace ticks every 0.25s, so it should not return drastically early.
    assert elapsed >= grace * 0.75
    # And it should not run substantially over (allow a generous ceiling
    # for slow CI VMs).
    assert elapsed < grace + 2.0


def test_grace_wait_emits_banner_exactly_once(free_port: int, stderr_log: Path) -> None:
    banners: list[str] = []
    mgr = AutoServeManager(
        preferred_port=free_port,
        grace_seconds=1,
        stderr_log_path=stderr_log,
        on_banner=banners.append,
        ready_timeout=15.0,
    )
    with mgr:
        mgr.grace_wait()
        # Second call is a no-op.
        mgr.grace_wait()

    # One "staying up" + one "shut down" banner — exactly one of each.
    staying = [b for b in banners if "staying up" in b]
    shutdown = [b for b in banners if "shut down" in b]
    assert len(staying) == 1, banners
    assert len(shutdown) == 1, banners


# ---------------------------------------------------------------------------
# L6 — Signal cascade: a SIGINT delivered while grace_wait blocks ends it
# ---------------------------------------------------------------------------


def test_sigint_during_grace_wait_returns_early(free_port: int, stderr_log: Path) -> None:
    """SIGINT mid-grace → grace_wait returns within ~1s of the signal."""
    mgr = AutoServeManager(
        preferred_port=free_port,
        grace_seconds=30,
        stderr_log_path=stderr_log,
        ready_timeout=15.0,
        on_banner=lambda s: None,
    )

    def _interrupt_after(delay: float) -> None:
        time.sleep(delay)
        os.kill(os.getpid(), signal.SIGINT)

    with mgr:
        t0 = time.monotonic()
        threading.Thread(target=_interrupt_after, args=(0.3,), daemon=True).start()
        # Some interpreters surface SIGINT inside grace_wait via
        # KeyboardInterrupt even with the signal handler installed.
        with contextlib.suppress(KeyboardInterrupt):
            mgr.grace_wait()
        elapsed = time.monotonic() - t0

    assert elapsed < 5.0, f"grace_wait did not return promptly after SIGINT (took {elapsed:.2f}s)"


# ---------------------------------------------------------------------------
# L7 — Multi-scan: a second AutoServeManager reuses the first one's serve
# ---------------------------------------------------------------------------


def test_back_to_back_managers_share_one_serve(
    manual_serve: tuple[subprocess.Popen[bytes], int],
    stderr_log: Path,
) -> None:
    _, port = manual_serve

    # First scan reuses (reuse is opt-in now).
    with AutoServeManager(
        preferred_port=port,
        grace_seconds=0,
        stderr_log_path=stderr_log,
        reuse_existing=True,
    ) as r1:
        assert r1.reused is True

    # Second scan immediately after — same serve still alive, same reuse.
    with AutoServeManager(
        preferred_port=port,
        grace_seconds=0,
        stderr_log_path=stderr_log,
        reuse_existing=True,
    ) as r2:
        assert r2.reused is True
        assert r2.spawned is False


# ---------------------------------------------------------------------------
# L8 — Probe correctness against a real serve
# ---------------------------------------------------------------------------


def test_probe_recognises_real_serve(
    manual_serve: tuple[subprocess.Popen[bytes], int],
) -> None:
    _, port = manual_serve
    assert probe_is_our_serve("127.0.0.1", port) is True


def test_probe_returns_false_after_serve_terminates(
    stderr_log: Path,
) -> None:
    port = _free_port()
    child = _spawn_serve(port, log_path=stderr_log)
    try:
        if not wait_until_ready(port, timeout=15.0):
            pytest.skip("serve never came up")
        assert probe_is_our_serve("127.0.0.1", port) is True
    finally:
        _terminate_pg(child)

    # After termination the probe must report False.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not probe_is_our_serve("127.0.0.1", port, timeout=0.3):
            break
        time.sleep(0.1)
    assert probe_is_our_serve("127.0.0.1", port, timeout=0.3) is False


# ---------------------------------------------------------------------------
# L9 — Stale stderr log path is created on demand
# ---------------------------------------------------------------------------


def test_stderr_log_directory_is_created(tmp_path: Path, free_port: int) -> None:
    nested = tmp_path / "deep" / "nested" / "auto_serve.log"
    mgr = AutoServeManager(
        preferred_port=free_port,
        grace_seconds=0,
        stderr_log_path=nested,
        ready_timeout=15.0,
    )
    with mgr as result:
        assert result.spawned is True
        assert nested.exists()


# ---------------------------------------------------------------------------
# L10 — URL reachability survives the grace window
# ---------------------------------------------------------------------------


def test_dashboard_stays_reachable_during_grace(free_port: int, stderr_log: Path) -> None:
    grace = 2
    mgr = AutoServeManager(
        preferred_port=free_port,
        grace_seconds=grace,
        stderr_log_path=stderr_log,
        ready_timeout=15.0,
        on_banner=lambda s: None,
    )
    with mgr as result:
        # Check at t=0 + at t=grace*0.5 + at t=grace - 0.25.
        with urlopen(f"{result.base_url}/healthz", timeout=2.0) as resp:
            assert resp.status == 200
        time.sleep(grace * 0.5)
        with urlopen(f"{result.base_url}/healthz", timeout=2.0) as resp:
            assert resp.status == 200
        mgr.grace_wait()

    # After __exit__, the URL should fail (allow a small grace period
    # for the OS to fully tear down the listener).
    deadline = time.monotonic() + 5.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{free_port}/healthz", timeout=0.5) as resp:
                # Still up — let it finish dying.
                _ = resp.status
        except (URLError, ConnectionError, OSError) as exc:
            last_err = exc
            break
        time.sleep(0.2)
    assert last_err is not None, "dashboard remained reachable after manager.__exit__"
