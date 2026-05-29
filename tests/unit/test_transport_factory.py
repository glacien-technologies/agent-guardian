"""Unit tests for the contract → transport factory (Stage 1B).

Covers :func:`build_auth_provider` (one arm per discriminated auth ``kind``,
each resolving its :class:`SecretRef` against a monkeypatched env / file),
:func:`build_transport` (HTTP field mapping + the unsupported-kind guard), and
:func:`build_session_machine` (mode mapping).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from agent_guardian.contract.schema import (
    ApiKeyAuth,
    BearerAuth,
    Contract,
    HmacAuth,
    MtlsAuth,
    NoAuth,
    OAuth2ClientCredentialsAuth,
    Request,
    Response,
    ResponseError,
    Session,
    Target,
    ToolRef,
    Tools,
)
from agent_guardian.contract.schema import (
    HttpTransport as ContractHttpTransport,
)
from agent_guardian.contract.secrets import SecretRef, SecretResolver
from agent_guardian.transports.auth.api_key import ApiKeyAuth as ProviderApiKeyAuth
from agent_guardian.transports.auth.base import AuthContext
from agent_guardian.transports.auth.base import NoAuth as ProviderNoAuth
from agent_guardian.transports.auth.bearer import BearerAuth as ProviderBearerAuth
from agent_guardian.transports.auth.hmac import HmacAuth as ProviderHmacAuth
from agent_guardian.transports.auth.mtls import MutualTlsAuth
from agent_guardian.transports.auth.oauth2 import OAuth2ClientCredentialsAuth as ProviderOAuth2
from agent_guardian.transports.factory import (
    build_auth_provider,
    build_session_machine,
    build_transport,
)
from agent_guardian.transports.http import HttpTransport
from agent_guardian.transports.session import SessionMode

URL = "https://api.example.com/v1/chat"


def _contract(*, auth: Any = None, **target_overrides: Any) -> Contract:
    """Build a minimal valid HTTP contract with an optional auth block."""
    base: dict[str, Any] = {
        "name": "demo",
        "transport": ContractHttpTransport(url=URL),  # type: ignore[arg-type]
        "response": Response(output_path="$.output.text"),
    }
    if auth is not None:
        base["auth"] = auth
    base.update(target_overrides)
    return Contract(target=Target(**base))


def _ctx() -> AuthContext:
    return AuthContext(method="POST", url=URL, body=b"{}")


# ---------------------------------------------------------------------------
# build_auth_provider — one arm per kind, resolving secrets
# ---------------------------------------------------------------------------


def test_auth_none_returns_noauth() -> None:
    provider = build_auth_provider(_contract(auth=NoAuth()))
    assert isinstance(provider, ProviderNoAuth)


async def test_auth_api_key_resolves_secret_and_folds_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AG_KEY", "sk-resolved-123")
    contract = _contract(
        auth=ApiKeyAuth.model_validate(
            {"name": "Authorization", "prefix": "Bearer ", "value": "${env:AG_KEY}"}
        )
    )
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderApiKeyAuth)
    ctx = _ctx()
    await provider.apply(ctx)
    # prefix is folded into the value template → "Bearer <key>"
    assert ctx.headers["Authorization"] == "Bearer sk-resolved-123"


async def test_auth_api_key_no_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AG_KEY2", "rawkey")
    contract = _contract(
        auth=ApiKeyAuth.model_validate({"name": "x-api-key", "value": "${env:AG_KEY2}"})
    )
    provider = build_auth_provider(contract)
    ctx = _ctx()
    await provider.apply(ctx)
    assert ctx.headers["x-api-key"] == "rawkey"


async def test_auth_bearer_resolves_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEARER_TOK", "tok-xyz")
    contract = _contract(auth=BearerAuth(token=SecretRef("${env:BEARER_TOK}")))
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderBearerAuth)
    ctx = _ctx()
    await provider.apply(ctx)
    assert ctx.headers["Authorization"] == "Bearer tok-xyz"


async def test_auth_oauth2_resolves_secrets_and_uses_injected_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CID", "client-id-1")
    monkeypatch.setenv("CSEC", "client-secret-1")
    contract = _contract(
        auth=OAuth2ClientCredentialsAuth.model_validate(
            {
                "token_url": "https://auth.example.com/token",
                "client_id": "${env:CID}",
                "client_secret": "${env:CSEC}",
                "scope": "chat.read",
            }
        )
    )
    async with httpx.AsyncClient() as client:
        provider = build_auth_provider(contract, oauth2_client=client)
        assert isinstance(provider, ProviderOAuth2)


def test_auth_oauth2_without_client_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CID", "c")
    monkeypatch.setenv("CSEC", "s")
    contract = _contract(
        auth=OAuth2ClientCredentialsAuth.model_validate(
            {
                "token_url": "https://auth.example.com/token",
                "client_id": "${env:CID}",
                "client_secret": "${env:CSEC}",
            }
        )
    )
    with pytest.raises(ValueError, match="oauth2_client_credentials"):
        build_auth_provider(contract)


async def test_auth_mtls_resolves_cert_key_and_ca(tmp_path: Path) -> None:
    cert_file = tmp_path / "client.pem"
    key_file = tmp_path / "client.key"
    ca_file = tmp_path / "ca.pem"
    cert_file.write_text("CERT-MATERIAL")
    key_file.write_text("KEY-MATERIAL")
    ca_file.write_text("CA-MATERIAL")
    contract = _contract(
        auth=MtlsAuth(
            client_cert=SecretRef(f"${{file:{cert_file}}}"),
            client_key=SecretRef(f"${{file:{key_file}}}"),
            ca_bundle=SecretRef(f"${{file:{ca_file}}}"),
        )
    )
    provider = build_auth_provider(contract)
    assert isinstance(provider, MutualTlsAuth)
    assert provider.cert == ("CERT-MATERIAL", "KEY-MATERIAL")
    assert provider.verify == "CA-MATERIAL"


async def test_auth_mtls_without_ca_defaults_verify_true(tmp_path: Path) -> None:
    cert_file = tmp_path / "client.pem"
    key_file = tmp_path / "client.key"
    cert_file.write_text("C")
    key_file.write_text("K")
    contract = _contract(
        auth=MtlsAuth(
            client_cert=SecretRef(f"${{file:{cert_file}}}"),
            client_key=SecretRef(f"${{file:{key_file}}}"),
        )
    )
    provider = build_auth_provider(contract)
    assert isinstance(provider, MutualTlsAuth)
    assert provider.verify is True


async def test_auth_hmac_resolves_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HMAC_SECRET", "shh")
    contract = _contract(
        auth=HmacAuth(
            header="x-signature",
            secret=SecretRef("${env:HMAC_SECRET}"),
            signing_string_template="{method}\n{path}\n{body}",
        )
    )
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderHmacAuth)
    ctx = _ctx()
    await provider.apply(ctx)
    assert "x-signature" in ctx.headers


def test_auth_provider_accepts_injected_resolver() -> None:
    contract = _contract(auth=BearerAuth(token=SecretRef("${env:INJECTED}")))
    resolver = SecretResolver(env={"INJECTED": "from-injected-resolver"})
    provider = build_auth_provider(contract, resolver=resolver)
    assert isinstance(provider, ProviderBearerAuth)


# ---------------------------------------------------------------------------
# build_transport — HTTP field mapping + unsupported-kind guard
# ---------------------------------------------------------------------------


def test_build_transport_maps_http_fields() -> None:
    contract = _contract(
        transport=ContractHttpTransport.model_validate(
            {
                "url": URL,
                "headers": {"X-Client": "ag"},
                "timeout_ms": 20000,
            }
        ),
        request=Request(body='{"prompt": "{{ prompt }}"}'),
        response=Response(
            output_path="$.choices[0].message.content",
            error=ResponseError(error_path="$.error.message"),
            tool_call_path="$.choices[0].message.tool_calls",
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, HttpTransport)
    assert transport.endpoint == URL
    # Inspect the mapped primitives via the transport's private fields.
    assert transport._request_template == '{"prompt": "{{ prompt }}"}'
    assert transport._output_path == "$.choices[0].message.content"
    assert transport._error_path == "$.error.message"
    assert transport._tool_call_path == "$.choices[0].message.tool_calls"
    assert transport._base_headers == {"X-Client": "ag"}
    # timeout_ms (20000) → timeout_seconds (20.0) on the underlying adapter.
    assert transport._adapter._timeout_seconds == pytest.approx(20.0)


def test_build_transport_no_error_path_is_none() -> None:
    contract = _contract()
    transport = build_transport(contract)
    assert isinstance(transport, HttpTransport)
    assert transport._error_path is None
    assert transport._tool_call_path is None


async def test_build_transport_oauth2_builds_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CID", "c")
    monkeypatch.setenv("CSEC", "s")
    contract = _contract(
        auth=OAuth2ClientCredentialsAuth.model_validate(
            {
                "token_url": "https://auth.example.com/token",
                "client_id": "${env:CID}",
                "client_secret": "${env:CSEC}",
            }
        )
    )
    transport = build_transport(contract)
    assert isinstance(transport, HttpTransport)
    await transport.aclose()


def test_build_transport_unsupported_kind_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    contract = _contract()
    # Force a non-http kind through the frozen model to exercise the guard.
    object.__setattr__(contract.target.transport, "kind", "grpc")
    with pytest.raises(NotImplementedError, match="grpc"):
        build_transport(contract)


# ---------------------------------------------------------------------------
# build_session_machine — mode mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("stateless", SessionMode.STATELESS),
        ("server_session", SessionMode.SERVER_SESSION),
        ("client_history", SessionMode.CLIENT_HISTORY),
    ],
)
def test_build_session_machine_maps_mode(mode: str, expected: SessionMode) -> None:
    contract = _contract(session=Session.model_validate({"mode": mode}))
    transport = build_transport(contract)
    machine = build_session_machine(contract, transport)
    assert machine.mode is expected


def test_fingerprint_declared_tools_via_full_build() -> None:
    # Exercised here so the factory's interaction with declared tools is covered.
    contract = _contract(
        tools=Tools(expected=[ToolRef(name="search"), ToolRef(name="email")]),
    )
    transport = build_transport(contract)
    assert isinstance(transport, HttpTransport)
