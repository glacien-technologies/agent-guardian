"""Tests for the dashboard auth dependency.

The token mode is the launch-readiness blocker: when a token is configured,
the dashboard must refuse off-loopback reads without a valid Bearer / signed
cookie. Zero-config (no token) keeps the dashboard fully open so local-dev
and the existing TestClient flow stay green.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.auth import (
    AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV,
    DASHBOARD_SESSION_COOKIE,
    mint_session_cookie,
    require_dashboard_auth,
    resolve_dashboard_token,
    verify_session_cookie,
)


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


def _build_client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Zero-config (no token configured) — fully open
# ---------------------------------------------------------------------------


def test_home_open_when_no_token_configured(
    store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, raising=False)
    client = _build_client(store)
    resp = client.get("/")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Token configured — loopback bypass, Bearer success, no-auth fail
# ---------------------------------------------------------------------------


def test_home_allows_loopback_with_token_configured(
    store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, "s3cr3t-abc")
    client = _build_client(store)
    # TestClient.client.host == "testclient" which we treat as loopback.
    resp = client.get("/")
    assert resp.status_code == 200


def test_home_allows_valid_bearer_off_loopback(
    store: ScanStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request with a valid Bearer token is permitted regardless of host."""
    token = "s3cr3t-abc"
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, token)
    # Direct exercise of the dependency to simulate an off-loopback client
    # (TestClient always reports host=testclient, which would bypass).
    remote = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={"authorization": f"Bearer {token}"},
        cookies={},
        app=SimpleNamespace(state=SimpleNamespace(dashboard_token=token)),
    )
    require_dashboard_auth(remote)  # type: ignore[arg-type]


def test_home_rejects_off_loopback_without_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off-loopback, no Bearer, no cookie → 401."""
    token = "s3cr3t-abc"
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, token)
    remote = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={},
        cookies={},
        app=SimpleNamespace(state=SimpleNamespace(dashboard_token=token)),
    )
    with pytest.raises(Exception) as exc:
        require_dashboard_auth(remote)  # type: ignore[arg-type]
    # 401 with WWW-Authenticate header.
    assert getattr(exc.value, "status_code", None) == 401
    headers = getattr(exc.value, "headers", {}) or {}
    assert "WWW-Authenticate" in headers
    assert headers["WWW-Authenticate"].startswith("Bearer")


def test_home_rejects_wrong_bearer_off_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "s3cr3t-abc"
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, token)
    remote = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={"authorization": "Bearer wrong-token"},
        cookies={},
        app=SimpleNamespace(state=SimpleNamespace(dashboard_token=token)),
    )
    with pytest.raises(Exception) as exc:
        require_dashboard_auth(remote)  # type: ignore[arg-type]
    assert getattr(exc.value, "status_code", None) == 401


def test_home_rejects_malformed_authorization_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "s3cr3t-abc"
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, token)
    remote = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        # Basic auth — not the scheme we accept.
        headers={"authorization": f"Basic {token}"},
        cookies={},
        app=SimpleNamespace(state=SimpleNamespace(dashboard_token=token)),
    )
    with pytest.raises(Exception) as exc:
        require_dashboard_auth(remote)  # type: ignore[arg-type]
    assert getattr(exc.value, "status_code", None) == 401


# ---------------------------------------------------------------------------
# Signed cookie path
# ---------------------------------------------------------------------------


def test_signed_cookie_unlocks_off_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "s3cr3t-abc"
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, token)
    cookie = mint_session_cookie(token)
    remote = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={},
        cookies={DASHBOARD_SESSION_COOKIE: cookie},
        app=SimpleNamespace(state=SimpleNamespace(dashboard_token=token)),
    )
    require_dashboard_auth(remote)  # type: ignore[arg-type]


def test_signed_cookie_with_wrong_value_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "s3cr3t-abc"
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, token)
    remote = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.7"),
        headers={},
        cookies={DASHBOARD_SESSION_COOKIE: "deadbeef" * 8},
        app=SimpleNamespace(state=SimpleNamespace(dashboard_token=token)),
    )
    with pytest.raises(Exception) as exc:
        require_dashboard_auth(remote)  # type: ignore[arg-type]
    assert getattr(exc.value, "status_code", None) == 401


def test_mint_session_cookie_is_deterministic() -> None:
    """Same token → same cookie value (the cookie is a pure HMAC)."""
    cookie_a = mint_session_cookie("token-1")
    cookie_b = mint_session_cookie("token-1")
    cookie_c = mint_session_cookie("token-2")
    assert cookie_a == cookie_b
    assert cookie_a != cookie_c
    # Reasonable cookie length (sha256 hex digest).
    assert len(cookie_a) == 64


def test_verify_session_cookie_returns_false_when_missing() -> None:
    remote = SimpleNamespace(cookies={})
    assert verify_session_cookie(remote, "any-token") is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Token resolution priority
# ---------------------------------------------------------------------------


def test_resolve_token_prefers_app_state_over_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, "from-env")
    remote = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(dashboard_token="from-state"))
    )
    assert resolve_dashboard_token(remote) == "from-state"  # type: ignore[arg-type]


def test_resolve_token_falls_back_to_env_when_state_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, "from-env")
    remote = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(dashboard_token=None)))
    assert resolve_dashboard_token(remote) == "from-env"  # type: ignore[arg-type]


def test_resolve_token_returns_none_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV, raising=False)
    remote = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(dashboard_token=None)))
    assert resolve_dashboard_token(remote) is None  # type: ignore[arg-type]
