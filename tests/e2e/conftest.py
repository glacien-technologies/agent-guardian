"""Session-scope fixtures for the Playwright E2E test suite.

Spawns a real ``uvicorn`` subprocess running ``agent_guardian.server.app``
with ``AGENT_GUARDIAN_TEST_HOOKS=1`` enabled so the Playwright pages can
drive the test-only ``/test/*`` endpoints. The scan store points at a
per-session tmp dir so tests do not race the user's local dashboard
state.

Why a subprocess and not FastAPI's ``TestClient``: ``TestClient`` runs
the ASGI app in the same event loop Playwright uses, which races and
deadlocks on streaming endpoints (FastAPI #5446). A real uvicorn
subprocess matches production behaviour exactly.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

import httpx
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
_STARTUP_TIMEOUT_S = 15.0


def _pick_free_port() -> int:
    """Bind to port 0 to get a free port, then close. Race-prone but fine
    for a session-scope fixture started once per pytest run."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_ready(base_url: str) -> None:
    deadline = time.monotonic() + _STARTUP_TIMEOUT_S
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(Request(base_url + "/healthz"), timeout=1.0) as resp:
                if 200 <= resp.status < 300:
                    return
        except Exception as exc:  # pragma: no cover — startup race
            last_err = exc
            time.sleep(0.2)
    raise RuntimeError(f"uvicorn never became ready at {base_url} (last err: {last_err!r})")


@pytest.fixture(scope="session")
def uvicorn_server(tmp_path_factory: pytest.TempPathFactory) -> object:
    """Spawn the dashboard backend for the test session. Yields the base URL."""
    scan_store_dir = tmp_path_factory.mktemp("e2e_scan_store")
    port = _pick_free_port()
    env = {
        **os.environ,
        "AGENT_GUARDIAN_TEST_HOOKS": "1",
        "AGENT_GUARDIAN_SCAN_STORE_ROOT": str(scan_store_dir),
        "AGENT_GUARDIAN_E2E_FIXTURES": str(_FIXTURES_DIR),
        "PYTHONUNBUFFERED": "1",
    }
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "agent_guardian.server.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-access-log",
        ],
        cwd=_REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_ready(base_url)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def loaded_baseline(uvicorn_server: str) -> str:
    """Load the ``finbot-baseline`` fixture into the running server and yield
    its scan_id. The fixture is loaded fresh per test so each test sees a
    deterministic dashboard state."""
    resp = httpx.post(
        f"{uvicorn_server}/test/fixtures/load",
        json={"name": "finbot-baseline"},
        timeout=5.0,
    )
    resp.raise_for_status()
    return resp.json()["scan_id"]


@pytest.fixture
def loaded_failed(uvicorn_server: str) -> str:
    """Load the ``finbot-failed`` fixture (a partial / crashed scan)."""
    resp = httpx.post(
        f"{uvicorn_server}/test/fixtures/load",
        json={"name": "finbot-failed"},
        timeout=5.0,
    )
    resp.raise_for_status()
    return resp.json()["scan_id"]
