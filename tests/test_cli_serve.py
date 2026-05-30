"""CLI ``serve`` command tests.

Pre-fix, ``serve`` had no ``--token`` / ``--insecure-no-auth`` flags
despite the auth module's docstring referring to them. Binding to a
non-loopback host emitted a stderr warning but still went through, so a
careless ``--host 0.0.0.0`` exposed the unauth'd dashboard to the
network. The regression tests below pin the post-fix behaviour:

* off-loopback bind without ``--token`` and without ``--insecure-no-auth``
  is REFUSED with ``EXIT_CONFIG``,
* off-loopback bind WITH ``--token`` succeeds and stamps the token onto
  ``app.state.dashboard_token`` (the auth dep reads from app.state first),
* off-loopback bind WITH ``--insecure-no-auth`` succeeds without a token,
* the ``--help`` output lists both new options.

We monkeypatch ``uvicorn.run`` everywhere so the tests don't actually
bind to a port.
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from agent_guardian.cli import EXIT_CONFIG, EXIT_OK, app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _combined_output(result: Any) -> str:
    stdout = result.stdout or ""
    try:
        stderr = result.stderr or ""
    except (AttributeError, ValueError):
        stderr = ""
    return stdout + stderr


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ensure no ambient AGENT_GUARDIAN_DASHBOARD_TOKEN leaks into the test.
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_TOKEN", raising=False)


def _patch_uvicorn_run(
    monkeypatch: pytest.MonkeyPatch,
) -> list[dict[str, Any]]:
    """Replace ``uvicorn.run`` with a stub that records its kwargs.

    Returns the list the stub appends to. The first positional/keyword
    ``app`` (the FastAPI instance) is preserved so the test can read
    ``app.state.dashboard_token`` afterwards.
    """
    import uvicorn

    captured: list[dict[str, Any]] = []

    def _fake_run(app_arg: Any, *args: Any, **kwargs: Any) -> None:
        captured.append({"app": app_arg, "args": args, "kwargs": kwargs})

    monkeypatch.setattr(uvicorn, "run", _fake_run)
    return captured


def test_serve_help_lists_new_options(runner: CliRunner) -> None:
    """``serve --help`` must surface the new ``--token`` + ``--insecure-no-auth``."""
    result = runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == EXIT_OK
    output = _combined_output(result)
    assert "--token" in output
    assert "--insecure-no-auth" in output


def test_serve_loopback_default_no_token_succeeds(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default 127.0.0.1 bind needs no token and goes through."""
    captured = _patch_uvicorn_run(monkeypatch)
    result = runner.invoke(app, ["serve"])
    assert result.exit_code == EXIT_OK
    assert len(captured) == 1
    # state should be stamped with None (no token).
    fastapi_app = captured[0]["app"]
    assert fastapi_app.state.dashboard_token is None


def test_serve_off_loopback_without_token_refused(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--host 0.0.0.0`` with no token AND no --insecure flag must refuse."""
    captured = _patch_uvicorn_run(monkeypatch)
    result = runner.invoke(app, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code == EXIT_CONFIG
    assert "refusing to bind" in _combined_output(result).lower()
    # uvicorn.run must NOT have been called.
    assert captured == []


def test_serve_off_loopback_with_token_succeeds_and_stamps_state(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--host 0.0.0.0 --token X`` succeeds and stamps app.state.dashboard_token."""
    captured = _patch_uvicorn_run(monkeypatch)
    result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--token", "s3cret-XYZ"])
    assert result.exit_code == EXIT_OK, _combined_output(result)
    assert len(captured) == 1
    fastapi_app = captured[0]["app"]
    assert fastapi_app.state.dashboard_token == "s3cret-XYZ"


def test_serve_off_loopback_insecure_no_auth_allowed(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--host 0.0.0.0 --insecure-no-auth`` is explicitly permitted with no token."""
    captured = _patch_uvicorn_run(monkeypatch)
    result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--insecure-no-auth"])
    assert result.exit_code == EXIT_OK, _combined_output(result)
    assert len(captured) == 1
    # Token left as None on app.state -- the auth dep's _is_loopback() gate
    # will refuse non-loopback writes without a configured token, but the
    # operator has explicitly accepted that the read views are unauthed.
    fastapi_app = captured[0]["app"]
    assert fastapi_app.state.dashboard_token is None
    # We warned them.
    assert "warning" in _combined_output(result).lower()


def test_serve_off_loopback_token_via_envvar(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``AGENT_GUARDIAN_DASHBOARD_TOKEN`` env var also satisfies the auth check."""
    monkeypatch.setenv("AGENT_GUARDIAN_DASHBOARD_TOKEN", "from-env-XYZ")
    captured = _patch_uvicorn_run(monkeypatch)
    result = runner.invoke(app, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code == EXIT_OK, _combined_output(result)
    assert len(captured) == 1
    fastapi_app = captured[0]["app"]
    assert fastapi_app.state.dashboard_token == "from-env-XYZ"


def test_serve_reload_off_loopback_with_token_uses_envvar_handoff(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reload-mode imports the factory in a child; token rides via env var."""
    captured = _patch_uvicorn_run(monkeypatch)
    monkeypatch.delenv("AGENT_GUARDIAN_DASHBOARD_TOKEN", raising=False)
    result = runner.invoke(
        app,
        [
            "serve",
            "--host",
            "0.0.0.0",
            "--reload",
            "--token",
            "reload-handoff",
        ],
    )
    assert result.exit_code == EXIT_OK, _combined_output(result)
    assert len(captured) == 1
    # In reload mode, uvicorn.run gets an import string, not the FastAPI app.
    assert captured[0]["app"] == "agent_guardian.server.app:create_app"
    # The env var must have been set so the reload-child factory picks it up.
    import os as _os

    assert _os.environ.get("AGENT_GUARDIAN_DASHBOARD_TOKEN") == "reload-handoff"


# ---------------------------------------------------------------------------
# Regression: --otel-endpoint must reach the contract path when the contract
# has no observability stanza (was silently dropped pre-fix).
# ---------------------------------------------------------------------------


def test_contract_scan_context_uses_flag_otel_endpoint_when_contract_silent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """_ContractScanContext: contract has no observability -> flag wins."""
    from agent_guardian.cli import _ContractScanContext

    captured: list[str | None] = []

    def _fake_configure_otel(endpoint: str | None) -> None:
        captured.append(endpoint)

    def _fake_make_observer() -> object:
        return object()

    # Monkeypatch the OTel seam at its source.
    import agent_guardian.obs.otel as otel_mod

    monkeypatch.setattr(otel_mod, "configure_otel", _fake_configure_otel)
    monkeypatch.setattr(otel_mod, "make_otel_observer", _fake_make_observer)

    # Build a minimal contract with observability=None.
    class _Fake:
        pass

    fake_contract = _Fake()
    fake_contract.observability = None
    fake_contract.version = "1.0.0"
    fake_target = _Fake()
    fake_target.environment = "lab"
    fake_target.name = "fake"
    fake_contract.target = fake_target
    fake_roe = _Fake()
    fake_roe.authorization_ref = "owner@example.com"
    fake_contract.roe = fake_roe

    def _fake_load_contract(_path: Any) -> Any:
        return fake_contract

    def _fake_contract_sha256(_c: Any) -> str:
        return "fake-sha"

    def _fake_authorization_gate(_c: Any) -> None:
        return None

    class _FakeRoe:
        def swarm_overrides(self) -> dict[str, Any]:
            return {}

    def _fake_from_contract(_c: Any) -> _FakeRoe:
        return _FakeRoe()

    def _fake_build_adapter(_c: Any, *, roe: Any) -> object:
        return object()

    import agent_guardian.contract as contract_mod
    import agent_guardian.core.roe as roe_mod
    import agent_guardian.transports.contract_adapter as tx_mod

    monkeypatch.setattr(contract_mod, "load_contract", _fake_load_contract)
    monkeypatch.setattr(contract_mod, "contract_sha256", _fake_contract_sha256)
    monkeypatch.setattr(roe_mod, "authorization_gate", _fake_authorization_gate)
    monkeypatch.setattr(roe_mod.RoeController, "from_contract", staticmethod(_fake_from_contract))
    monkeypatch.setattr(tx_mod, "build_contract_target_adapter", _fake_build_adapter)

    # Contract has no observability and the flag is set -> flag wins.
    _ContractScanContext(tmp_path / "fake.yaml", otel_endpoint="http://localhost:4318/v1/traces")
    assert captured == ["http://localhost:4318/v1/traces"]


def test_contract_scan_context_contract_otel_endpoint_wins_over_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """_ContractScanContext: contract.observability.otel_endpoint wins over flag."""
    from agent_guardian.cli import _ContractScanContext

    captured: list[str | None] = []

    def _fake_configure_otel(endpoint: str | None) -> None:
        captured.append(endpoint)

    def _fake_make_observer() -> object:
        return object()

    import agent_guardian.obs.otel as otel_mod

    monkeypatch.setattr(otel_mod, "configure_otel", _fake_configure_otel)
    monkeypatch.setattr(otel_mod, "make_otel_observer", _fake_make_observer)

    class _Fake:
        pass

    fake_obs = _Fake()
    fake_obs.otel_endpoint = "http://contract-collector:4318/v1/traces"

    fake_contract = _Fake()
    fake_contract.observability = fake_obs
    fake_contract.version = "1.0.0"
    fake_target = _Fake()
    fake_target.environment = "lab"
    fake_target.name = "fake"
    fake_contract.target = fake_target
    fake_roe = _Fake()
    fake_roe.authorization_ref = "owner@example.com"
    fake_contract.roe = fake_roe

    def _fake_load_contract(_path: Any) -> Any:
        return fake_contract

    def _fake_contract_sha256(_c: Any) -> str:
        return "fake-sha"

    def _fake_authorization_gate(_c: Any) -> None:
        return None

    class _FakeRoe:
        def swarm_overrides(self) -> dict[str, Any]:
            return {}

    def _fake_from_contract(_c: Any) -> _FakeRoe:
        return _FakeRoe()

    def _fake_build_adapter(_c: Any, *, roe: Any) -> object:
        return object()

    import agent_guardian.contract as contract_mod
    import agent_guardian.core.roe as roe_mod
    import agent_guardian.transports.contract_adapter as tx_mod

    monkeypatch.setattr(contract_mod, "load_contract", _fake_load_contract)
    monkeypatch.setattr(contract_mod, "contract_sha256", _fake_contract_sha256)
    monkeypatch.setattr(roe_mod, "authorization_gate", _fake_authorization_gate)
    monkeypatch.setattr(roe_mod.RoeController, "from_contract", staticmethod(_fake_from_contract))
    monkeypatch.setattr(tx_mod, "build_contract_target_adapter", _fake_build_adapter)

    _ContractScanContext(
        tmp_path / "fake.yaml", otel_endpoint="http://flag-collector:4318/v1/traces"
    )
    # Contract wins.
    assert captured == ["http://contract-collector:4318/v1/traces"]


# ---------------------------------------------------------------------------
# Regression: ScanStore.load_completed back-compat shim for legacy scans
# (pre-72d4deb stored scans had no ``mode`` field). Without the shim the
# dashboard would silently drop every legacy scan as a Pydantic ValidationError.
# ---------------------------------------------------------------------------


def _legacy_scan_payload(scan_id: str, *, include_mode: bool = False) -> dict[str, Any]:
    """A minimal Scan-model payload (legacy = missing the ``mode`` field)."""
    payload: dict[str, Any] = {
        "id": scan_id,
        "package_version": "0.0.0",
        "aivss_formula_version": "v1.1",
        "probe_library_version": "2026.05",
        "target_mode": "prompt",
        "target_ref": "fake://target",
        "tier": "T1",
        "aivss": 50,
        "band": "POOR",
        "sub_scores": {},
        "findings": [],
        "asi_scores": {},
        "duration_seconds": 1.0,
        "cost_usd": 0.0,
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    if include_mode:
        payload["mode"] = "full"
        payload["mode_authoritative"] = True
    return payload


def test_scan_store_legacy_scan_without_mode_backcompat(tmp_path: Any) -> None:
    """A legacy scan.json missing ``mode`` loads as smart + non-authoritative."""
    import json as _json

    from agent_guardian.server.scan_store import ScanStore

    scan_id = "cli-legacy0001"
    scan_dir = tmp_path / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    legacy_payload = _legacy_scan_payload(scan_id, include_mode=False)
    assert "mode" not in legacy_payload  # double-check the fixture is legacy
    (scan_dir / "scan.json").write_text(_json.dumps(legacy_payload), encoding="utf-8")

    store = ScanStore(root_dir=tmp_path)
    scan = store.load_completed(scan_id)
    assert scan is not None, "legacy scan must load via the back-compat shim"
    assert scan.mode == "smart"
    assert scan.mode_authoritative is False


def test_scan_store_modern_scan_with_mode_unchanged(tmp_path: Any) -> None:
    """A scan that already declares ``mode=full`` keeps its declared mode."""
    import json as _json

    from agent_guardian.server.scan_store import ScanStore

    scan_id = "cli-modern0001"
    scan_dir = tmp_path / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    modern_payload = _legacy_scan_payload(scan_id, include_mode=True)
    (scan_dir / "scan.json").write_text(_json.dumps(modern_payload), encoding="utf-8")

    store = ScanStore(root_dir=tmp_path)
    scan = store.load_completed(scan_id)
    assert scan is not None
    assert scan.mode == "full"
    assert scan.mode_authoritative is True
