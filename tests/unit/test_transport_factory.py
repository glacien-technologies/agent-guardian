"""Unit tests for the contract → transport factory (Stage 1B).

Covers :func:`build_auth_provider` (one arm per discriminated auth ``kind``,
each resolving its :class:`SecretRef` against a monkeypatched env / file),
:func:`build_transport` (HTTP field mapping + the unsupported-kind guard), and
:func:`build_session_machine` (mode mapping).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import httpx
import pytest

from agent_guardian.contract.schema import (
    AnthropicMessagesTransport as ContractAnthropicTransport,
)
from agent_guardian.contract.schema import (
    ApiKeyAuth,
    AwsSigV4Auth,
    AzureEntraAuth,
    BearerAuth,
    Contract,
    GcpAdcAuth,
    GcpSaJsonAuth,
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
    AzureFoundryAgentTransport as ContractAzureFoundryTransport,
)
from agent_guardian.contract.schema import (
    BedrockAgentTransport as ContractBedrockTransport,
)
from agent_guardian.contract.schema import (
    BrowserTransport as ContractBrowserTransport,
)
from agent_guardian.contract.schema import (
    GrpcTransport as ContractGrpcTransport,
)
from agent_guardian.contract.schema import (
    HttpTransport as ContractHttpTransport,
)
from agent_guardian.contract.schema import (
    McpOAuthAuth as ContractMcpOAuthAuth,
)
from agent_guardian.contract.schema import (
    McpTransport as ContractMcpTransport,
)
from agent_guardian.contract.schema import (
    OpenAiResponsesTransport as ContractOpenAiTransport,
)
from agent_guardian.contract.schema import (
    SdkTransport as ContractSdkTransport,
)
from agent_guardian.contract.schema import (
    SubprocessTransport as ContractSubprocessTransport,
)
from agent_guardian.contract.schema import (
    VertexAgentTransport as ContractVertexTransport,
)
from agent_guardian.contract.schema import (
    WebSocketTransport as ContractWebSocketTransport,
)
from agent_guardian.contract.secrets import SecretRef, SecretResolver
from agent_guardian.transports.anthropic_messages import AnthropicMessagesTransport
from agent_guardian.transports.auth.api_key import ApiKeyAuth as ProviderApiKeyAuth
from agent_guardian.transports.auth.azure_entra import AzureEntraAuth as ProviderAzureEntraAuth
from agent_guardian.transports.auth.base import AuthContext
from agent_guardian.transports.auth.base import NoAuth as ProviderNoAuth
from agent_guardian.transports.auth.bearer import BearerAuth as ProviderBearerAuth
from agent_guardian.transports.auth.gcp import GcpAdcAuth as ProviderGcpAdcAuth
from agent_guardian.transports.auth.gcp import GcpSaJsonAuth as ProviderGcpSaJsonAuth
from agent_guardian.transports.auth.hmac import HmacAuth as ProviderHmacAuth
from agent_guardian.transports.auth.mcp_oauth import McpOAuthProvider
from agent_guardian.transports.auth.mtls import MutualTlsAuth
from agent_guardian.transports.auth.oauth2 import OAuth2ClientCredentialsAuth as ProviderOAuth2
from agent_guardian.transports.auth.sigv4 import AwsSigV4Auth as ProviderAwsSigV4Auth
from agent_guardian.transports.azure_foundry import AzureFoundryAgentTransport
from agent_guardian.transports.base import Request as TransportRequest
from agent_guardian.transports.bedrock_agent import BedrockAgentTransport
from agent_guardian.transports.browser import BrowserTransport
from agent_guardian.transports.factory import (
    build_auth_provider,
    build_session_machine,
    build_transport,
)
from agent_guardian.transports.grpc_transport import GrpcTransport
from agent_guardian.transports.http import HttpTransport
from agent_guardian.transports.mcp import McpTransport
from agent_guardian.transports.openai_responses import OpenAiResponsesTransport
from agent_guardian.transports.sdk import SdkTransport
from agent_guardian.transports.session import SessionMode
from agent_guardian.transports.subprocess import SubprocessTransport
from agent_guardian.transports.vertex_agent import VertexAgentTransport
from agent_guardian.transports.websocket import WebSocketTransport

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


def _cloud_contract(*, transport: Any, auth: Any = None) -> Contract:
    """Build a minimal valid contract around a non-HTTP cloud transport.

    The schema still requires a ``response`` block even though the cloud
    transports parse their own provider shapes, so a dummy ``output_path`` is
    supplied.
    """
    base: dict[str, Any] = {
        "name": "cloud-demo",
        "transport": transport,
        "response": Response(output_path="$.output"),
    }
    if auth is not None:
        base["auth"] = auth
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

    # The dispatch is now isinstance-based over the discriminated union, so the
    # defensive guard fires only for a transport object that is none of the known
    # contract transport models. Swap in a stand-in that carries a ``kind`` but is
    # not a union member to exercise it.
    class _UnknownTransport:
        kind = "grpc"

    object.__setattr__(contract.target, "transport", _UnknownTransport())
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


# ---------------------------------------------------------------------------
# build_auth_provider — cloud provider kinds
# ---------------------------------------------------------------------------


def test_auth_aws_sigv4_explicit_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_AK", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_SK", "secret-key-material")
    contract = _contract(
        auth=AwsSigV4Auth.model_validate(
            {
                "region": "us-east-1",
                "service": "bedrock",
                "access_key_id": "${env:AWS_AK}",
                "secret_access_key": "${env:AWS_SK}",
            }
        )
    )
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderAwsSigV4Auth)


def test_auth_aws_sigv4_no_explicit_credentials_uses_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With no explicit credentials the provider falls back to the botocore
    # default chain at construction; we monkeypatch a session so the test does
    # not depend on the host's AWS configuration.
    import botocore.session

    class _FakeCreds:
        access_key = "AK"
        secret_key = "SK"
        token = None

    class _FakeSession:
        def get_credentials(self) -> _FakeCreds:
            return _FakeCreds()

    monkeypatch.setattr(botocore.session, "Session", _FakeSession)
    contract = _contract(auth=AwsSigV4Auth.model_validate({"region": "eu-west-1"}))
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderAwsSigV4Auth)


async def test_auth_azure_entra_uses_injected_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZ_CID", "azure-client")
    monkeypatch.setenv("AZ_CSEC", "azure-secret")
    contract = _contract(
        auth=AzureEntraAuth.model_validate(
            {
                "tenant_id": "tenant-123",
                "client_id": "${env:AZ_CID}",
                "client_secret": "${env:AZ_CSEC}",
            }
        )
    )
    async with httpx.AsyncClient() as client:
        provider = build_auth_provider(contract, oauth2_client=client)
        assert isinstance(provider, ProviderAzureEntraAuth)


def test_auth_azure_entra_without_client_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZ_CID", "c")
    monkeypatch.setenv("AZ_CSEC", "s")
    contract = _contract(
        auth=AzureEntraAuth.model_validate(
            {
                "tenant_id": "t",
                "client_id": "${env:AZ_CID}",
                "client_secret": "${env:AZ_CSEC}",
            }
        )
    )
    with pytest.raises(ValueError, match="azure_entra"):
        build_auth_provider(contract)


def test_auth_gcp_adc(monkeypatch: pytest.MonkeyPatch) -> None:
    import google.auth

    class _FakeCreds:
        valid = True
        token = "ya29.fake"

        def refresh(self, _request: object) -> None:  # pragma: no cover - not hit
            return None

    monkeypatch.setattr(google.auth, "default", lambda scopes=None: (_FakeCreds(), "proj"))
    contract = _contract(auth=GcpAdcAuth())
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderGcpAdcAuth)


def test_auth_gcp_sa_json_resolves_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_SA", '{"type": "service_account", "project_id": "p"}')

    from google.oauth2 import service_account

    class _FakeCreds:
        valid = True
        token = "ya29.fake"

    captured: dict[str, Any] = {}

    def _from_info(info: dict[str, Any], scopes: list[str] | None = None) -> _FakeCreds:
        captured["info"] = info
        captured["scopes"] = scopes
        return _FakeCreds()

    monkeypatch.setattr(
        service_account.Credentials, "from_service_account_info", staticmethod(_from_info)
    )
    contract = _contract(
        auth=GcpSaJsonAuth.model_validate(
            {"service_account_json": "${env:GCP_SA}", "scopes": ["https://example/scope"]}
        )
    )
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderGcpSaJsonAuth)
    # The resolved JSON was parsed and threaded through to the provider.
    assert captured["info"]["project_id"] == "p"
    assert captured["scopes"] == ["https://example/scope"]


def test_auth_gcp_sa_json_default_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCP_SA", '{"type": "service_account"}')

    from google.oauth2 import service_account

    class _FakeCreds:
        valid = True
        token = "t"

    captured: dict[str, Any] = {}

    def _from_info(info: dict[str, Any], scopes: list[str] | None = None) -> _FakeCreds:
        captured["scopes"] = scopes
        return _FakeCreds()

    monkeypatch.setattr(
        service_account.Credentials, "from_service_account_info", staticmethod(_from_info)
    )
    contract = _contract(
        auth=GcpSaJsonAuth.model_validate({"service_account_json": "${env:GCP_SA}"})
    )
    provider = build_auth_provider(contract)
    assert isinstance(provider, ProviderGcpSaJsonAuth)
    # No contract scopes → the provider applies its cloud-platform default.
    assert captured["scopes"] == ["https://www.googleapis.com/auth/cloud-platform"]


# ---------------------------------------------------------------------------
# build_transport — cloud transport kinds
# ---------------------------------------------------------------------------


async def test_build_transport_openai_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OAI_KEY", "sk-openai")
    contract = _cloud_contract(
        transport=ContractOpenAiTransport.model_validate(
            {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini", "store": True}
        ),
        auth=BearerAuth(token=SecretRef("${env:OAI_KEY}")),
    )
    transport = build_transport(contract)
    assert isinstance(transport, OpenAiResponsesTransport)
    assert transport.endpoint == "https://api.openai.com/v1/responses"
    await transport.aclose()


async def test_build_transport_anthropic_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANT_KEY", "sk-ant")
    contract = _cloud_contract(
        transport=ContractAnthropicTransport.model_validate(
            {"model": "claude-3-5-sonnet-latest", "max_tokens": 512}
        ),
        auth=ApiKeyAuth.model_validate({"name": "x-api-key", "value": "${env:ANT_KEY}"}),
    )
    transport = build_transport(contract)
    assert isinstance(transport, AnthropicMessagesTransport)
    assert transport.endpoint.endswith("/messages")
    await transport.aclose()


async def test_build_transport_bedrock_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    import botocore.session

    class _FakeCreds:
        access_key = "AK"
        secret_key = "SK"
        token = None

    class _FakeSession:
        def get_credentials(self) -> _FakeCreds:
            return _FakeCreds()

    monkeypatch.setattr(botocore.session, "Session", _FakeSession)
    contract = _cloud_contract(
        transport=ContractBedrockTransport.model_validate(
            {"region": "us-east-1", "agent_id": "AGENT123", "agent_alias_id": "ALIAS1"}
        ),
        auth=AwsSigV4Auth.model_validate({"region": "us-east-1"}),
    )
    transport = build_transport(contract)
    assert isinstance(transport, BedrockAgentTransport)
    await transport.aclose()


async def test_build_transport_vertex_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    import google.auth

    class _FakeCreds:
        valid = True
        token = "ya29.fake"

    monkeypatch.setattr(google.auth, "default", lambda scopes=None: (_FakeCreds(), "proj"))
    contract = _cloud_contract(
        transport=ContractVertexTransport.model_validate(
            {"project": "proj-1", "location": "us-central1", "reasoning_engine_id": "1234567890"}
        ),
        auth=GcpAdcAuth(),
    )
    transport = build_transport(contract)
    assert isinstance(transport, VertexAgentTransport)
    assert "reasoningEngines/1234567890:query" in transport.endpoint
    await transport.aclose()


async def test_build_transport_azure_foundry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZ_CID", "azure-client")
    monkeypatch.setenv("AZ_CSEC", "azure-secret")
    contract = _cloud_contract(
        transport=ContractAzureFoundryTransport.model_validate(
            {"endpoint": "https://foundry.example.com", "agent_id": "asst_1"}
        ),
        auth=AzureEntraAuth.model_validate(
            {
                "tenant_id": "tenant-123",
                "client_id": "${env:AZ_CID}",
                "client_secret": "${env:AZ_CSEC}",
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, AzureFoundryAgentTransport)
    assert "/threads/runs" in transport.endpoint
    await transport.aclose()


# ---------------------------------------------------------------------------
# build_transport — server-session wiring (id_source / id_send) for http
# ---------------------------------------------------------------------------


def test_build_http_transport_wires_session_capture_and_replay() -> None:
    contract = _contract(
        session=Session.model_validate(
            {
                "mode": "server_session",
                "id_source": "$.session.id",
                "id_send": {"in": "header", "name": "X-Session-Id"},
            }
        )
    )
    transport = build_transport(contract)
    assert isinstance(transport, HttpTransport)
    # id_source -> session_path (capture); id_send.{in,name} -> outbound replay.
    assert transport._session_path == "$.session.id"
    assert transport._session_send_in == "header"
    assert transport._session_send_name == "X-Session-Id"


def test_build_http_transport_session_query_placement() -> None:
    contract = _contract(
        session=Session.model_validate(
            {
                "mode": "server_session",
                "id_source": "$.id",
                "id_send": {"in": "query", "name": "sid"},
            }
        )
    )
    transport = build_transport(contract)
    assert isinstance(transport, HttpTransport)
    assert transport._session_send_in == "query"
    assert transport._session_send_name == "sid"


def test_build_http_transport_no_session_send_is_none() -> None:
    contract = _contract(session=Session.model_validate({"mode": "stateless"}))
    transport = build_transport(contract)
    assert isinstance(transport, HttpTransport)
    assert transport._session_path is None
    assert transport._session_send_in is None
    assert transport._session_send_name is None


def test_build_session_machine_server_session_for_cloud_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A cloud transport that manages its own server session maps to SERVER_SESSION.
    monkeypatch.setenv("OAI_KEY", "sk-openai")
    contract = _cloud_contract(
        transport=ContractOpenAiTransport.model_validate({"model": "gpt-4o-mini"}),
        auth=BearerAuth(token=SecretRef("${env:OAI_KEY}")),
    )
    object.__setattr__(contract.target.session, "mode", "server_session")
    transport = build_transport(contract)
    machine = build_session_machine(contract, transport)
    assert machine.mode is SessionMode.SERVER_SESSION


# ---------------------------------------------------------------------------
# build_transport — MCP transport
# ---------------------------------------------------------------------------


MCP_URL = "https://mcp.example.com/rpc"


async def test_build_transport_mcp_maps_fields() -> None:
    contract = _cloud_contract(
        transport=ContractMcpTransport.model_validate(
            {
                "url": MCP_URL,
                "entry_tool": "run",
                "prompt_argument": "text",
                "init_timeout_ms": 15000,
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, McpTransport)
    assert transport.endpoint == MCP_URL
    # entry_tool / prompt_argument / timeout mapped from the contract fields.
    assert transport._entry_tool == "run"
    assert transport._prompt_argument == "text"
    # init_timeout_ms (15000) → timeout_seconds (15.0).
    assert transport._timeout_seconds == pytest.approx(15.0)
    # No RoE controller here, so the live tool gate stays unset until the adapter
    # wires it (covered in test_contract_adapter).
    assert transport._tool_gate is None
    await transport.aclose()


async def test_build_transport_mcp_defaults_no_auth() -> None:
    contract = _cloud_contract(
        transport=ContractMcpTransport.model_validate({"url": MCP_URL}),
    )
    transport = build_transport(contract)
    assert isinstance(transport, McpTransport)
    # No auth declared → NoAuth, default entry_tool/prompt_argument from schema.
    assert transport._entry_tool is None
    assert transport._prompt_argument == "input"
    assert isinstance(transport._auth, ProviderNoAuth)
    await transport.aclose()


# ---------------------------------------------------------------------------
# build_auth_provider — MCP OAuth 2.1 + PKCE
# ---------------------------------------------------------------------------


async def test_build_transport_mcp_with_oauth_builds_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MCP_CID", "mcp-client-id")
    monkeypatch.setenv("MCP_CSEC", "mcp-client-secret")
    contract = _cloud_contract(
        transport=ContractMcpTransport.model_validate({"url": MCP_URL, "entry_tool": "run"}),
        auth=ContractMcpOAuthAuth.model_validate(
            {
                "client_id": "${env:MCP_CID}",
                "client_secret": "${env:MCP_CSEC}",
                "scopes": ["mcp.read", "mcp.write"],
                "token_url": "https://auth.example.com/token",
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, McpTransport)
    # The MCP transport's auth provider is the OAuth 2.1 + PKCE provider, handed
    # a dedicated httpx client for its token round-trip (built by the factory).
    assert isinstance(transport._auth, McpOAuthProvider)
    await transport.aclose()


async def test_build_auth_provider_mcp_oauth_resolves_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MCP_CID", "cid")
    contract = _cloud_contract(
        transport=ContractMcpTransport.model_validate({"url": MCP_URL}),
        auth=ContractMcpOAuthAuth.model_validate(
            {
                "client_id": "${env:MCP_CID}",
                "scopes": ["mcp.read"],
                "resource": "https://mcp.example.com",
            }
        ),
    )
    async with httpx.AsyncClient() as client:
        provider = build_auth_provider(contract, oauth2_client=client)
        assert isinstance(provider, McpOAuthProvider)
        # A public client (no secret) carries a PKCE S256 challenge.
        assert provider.code_challenge_method == "S256"
        assert provider.scope == "mcp.read"


def test_build_auth_provider_mcp_oauth_without_client_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MCP_CID", "cid")
    contract = _cloud_contract(
        transport=ContractMcpTransport.model_validate({"url": MCP_URL}),
        auth=ContractMcpOAuthAuth.model_validate(
            {"client_id": "${env:MCP_CID}", "token_url": "https://auth.example.com/token"}
        ),
    )
    with pytest.raises(ValueError, match="mcp_oauth"):
        build_auth_provider(contract)


# ---------------------------------------------------------------------------
# build_transport — Stage 4 long-tail transports (ws/grpc/sdk/subprocess/browser)
# ---------------------------------------------------------------------------
#
# ``grpcio`` and ``playwright`` are not installed in the test venv (their
# transports fail-fast on import at construction), so we inject a minimal fake
# module into ``sys.modules`` before building the factory arm. ``websockets`` IS
# installed, so its arm builds against the real package.


def _install_fake_grpc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject a fake ``grpc`` module sufficient for GrpcTransport construction."""
    grpc_mod = ModuleType("grpc")
    grpc_mod.StatusCode = SimpleNamespace()  # type: ignore[attr-defined]
    grpc_mod.RpcError = type("RpcError", (Exception,), {})  # type: ignore[attr-defined]
    grpc_mod.ssl_channel_credentials = lambda: "fake-creds"  # type: ignore[attr-defined]
    grpc_mod.aio = SimpleNamespace(  # type: ignore[attr-defined]
        AioRpcError=type("AioRpcError", (Exception,), {}),
        secure_channel=lambda target, creds: SimpleNamespace(),
        insecure_channel=lambda target: SimpleNamespace(),
    )
    monkeypatch.setitem(sys.modules, "grpc", grpc_mod)


def _install_fake_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject a fake ``playwright.async_api`` sufficient for construction."""
    pkg = ModuleType("playwright")
    async_api = ModuleType("playwright.async_api")
    async_api.async_playwright = lambda: SimpleNamespace()  # type: ignore[attr-defined]
    async_api.Error = type("Error", (Exception,), {})  # type: ignore[attr-defined]
    async_api.TimeoutError = type("TimeoutError", (Exception,), {})  # type: ignore[attr-defined]
    pkg.async_api = async_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)


async def test_build_transport_websocket_maps_fields() -> None:
    contract = _cloud_contract(
        transport=ContractWebSocketTransport.model_validate(
            {
                "url": "wss://chat.example.com/ws",
                "send_template": '{"q": "{{ prompt }}"}',
                "output_path": "$.reply.text",
                "open_timeout_ms": 12000,
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, WebSocketTransport)
    assert transport.url == "wss://chat.example.com/ws"
    assert transport._send_template == '{"q": "{{ prompt }}"}'
    assert transport._output_path == "$.reply.text"
    # open_timeout_ms (12000) → timeout_seconds (12.0); default stateless mode.
    assert transport._timeout_seconds == pytest.approx(12.0)
    assert transport._session_mode == "stateless"
    await transport.aclose()


async def test_build_transport_websocket_client_history_mode() -> None:
    contract = _cloud_contract(
        transport=ContractWebSocketTransport.model_validate({"url": "wss://x.example.com/ws"}),
    )
    object.__setattr__(contract.target.session, "mode", "client_history")
    transport = build_transport(contract)
    assert isinstance(transport, WebSocketTransport)
    assert transport._session_mode == "client_history"
    await transport.aclose()


async def test_build_transport_websocket_with_auth_applies_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WS_TOK", "ws-bearer-tok")
    contract = _cloud_contract(
        transport=ContractWebSocketTransport.model_validate({"url": "wss://x.example.com/ws"}),
        auth=BearerAuth(token=SecretRef("${env:WS_TOK}")),
    )
    transport = build_transport(contract)
    assert isinstance(transport, WebSocketTransport)
    headers = await transport._build_headers()
    assert headers["Authorization"] == "Bearer ws-bearer-tok"
    await transport.aclose()


async def test_build_transport_grpc_maps_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    contract = _cloud_contract(
        transport=ContractGrpcTransport.model_validate(
            {
                "target": "agent.example.com:443",
                "service_method": "/pkg.Chat/Send",
                "output_field": "$.reply",
                "use_tls": True,
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, GrpcTransport)
    assert transport.target == "agent.example.com:443"
    assert transport._service_method == "/pkg.Chat/Send"
    assert transport._output_field == "$.reply"
    assert transport._use_tls is True
    await transport.aclose()


async def test_build_transport_grpc_with_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    monkeypatch.setenv("GRPC_TOK", "grpc-tok")
    contract = _cloud_contract(
        transport=ContractGrpcTransport.model_validate(
            {"target": "localhost:50051", "service_method": "/pkg.Svc/Method", "use_tls": False}
        ),
        auth=BearerAuth(token=SecretRef("${env:GRPC_TOK}")),
    )
    transport = build_transport(contract)
    assert isinstance(transport, GrpcTransport)
    # Auth is lowered into call metadata; the provider is the bearer provider.
    metadata = await transport._build_metadata(TransportRequest(prompt="hi"))
    assert ("authorization", "Bearer grpc-tok") in metadata
    await transport.aclose()


def test_build_transport_sdk_resolves_entrypoint() -> None:
    # The factory resolves the dotted entrypoint via SdkTransport (same logic as
    # CodeAdapter). Point it at a real callable in the stdlib so resolution works.
    contract = _cloud_contract(
        transport=ContractSdkTransport.model_validate({"entrypoint": "os.path:basename"}),
    )
    transport = build_transport(contract)
    assert isinstance(transport, SdkTransport)
    assert transport.ref == "os.path:basename"


async def test_build_transport_sdk_takes_no_auth_and_invokes() -> None:
    contract = _cloud_contract(
        transport=ContractSdkTransport.model_validate({"entrypoint": "os.path:basename"}),
    )
    transport = build_transport(contract)
    assert isinstance(transport, SdkTransport)
    # The wrapped callable runs in-process; no auth provider is involved.
    response = await transport.send(TransportRequest(prompt="/tmp/agent.log"))
    assert response.text == "agent.log"


def test_build_transport_subprocess_maps_fields() -> None:
    contract = _cloud_contract(
        transport=ContractSubprocessTransport.model_validate(
            {
                "command": ["python", "agent.py"],
                "prompt_mode": "arg",
                "output_mode": "stdout_json",
                "output_path": "$.reply",
                "timeout_ms": 45000,
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, SubprocessTransport)
    assert transport._command == ["python", "agent.py"]
    assert transport._prompt_mode == "arg"
    assert transport._output_mode == "stdout_json"
    assert transport._output_path == "$.reply"
    # timeout_ms (45000) → timeout_seconds (45.0).
    assert transport._timeout_seconds == pytest.approx(45.0)


def test_build_transport_subprocess_default_output_path_when_unset() -> None:
    # The contract leaves output_path unset (None); the factory falls back to the
    # transport's default JSONPath so stdout_json parsing still has a path.
    contract = _cloud_contract(
        transport=ContractSubprocessTransport.model_validate({"command": ["./agent"]}),
    )
    transport = build_transport(contract)
    assert isinstance(transport, SubprocessTransport)
    assert transport._output_path == "$.output"


def test_build_transport_browser_maps_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(monkeypatch)
    contract = _cloud_contract(
        transport=ContractBrowserTransport.model_validate(
            {
                "url": "https://chat.example.com/app",
                "input_selector": "#prompt",
                "submit_selector": "#send",
                "output_selector": "#reply",
                "nav_timeout_ms": 20000,
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, BrowserTransport)
    assert transport.url == "https://chat.example.com/app"
    assert transport._input_selector == "#prompt"
    assert transport._submit_selector == "#send"
    assert transport._output_selector == "#reply"
    assert transport._submit_with_enter is False
    assert transport._nav_timeout_ms == 20000


def test_build_transport_browser_submit_with_enter_when_no_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No submit_selector → the factory enables submit_with_enter so construction
    # succeeds (the transport requires one of the two).
    _install_fake_playwright(monkeypatch)
    contract = _cloud_contract(
        transport=ContractBrowserTransport.model_validate(
            {
                "url": "https://chat.example.com",
                "input_selector": "#prompt",
                "output_selector": "#reply",
            }
        ),
    )
    transport = build_transport(contract)
    assert isinstance(transport, BrowserTransport)
    assert transport._submit_selector is None
    assert transport._submit_with_enter is True
