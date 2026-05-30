"""Tests for ``AuthProvider.aclose`` + the transport-cascade close contract.

Token-fetch providers (OAuth2 client-credentials, Azure Entra, MCP OAuth) own an
injected ``httpx.AsyncClient`` for their token-endpoint round-trip. The transport
that owns the provider must cascade ``aclose`` into the provider so that client
cannot leak. These tests verify:

* The :class:`AuthProvider` ABC ships a default ``aclose`` that is a no-op
  (``NoAuth`` and any provider that does not own a client must succeed silently).
* :class:`OAuth2ClientCredentialsAuth`, :class:`AzureEntraAuth`, and
  :class:`McpOAuthProvider` override ``aclose`` to close their internal client.
* Every transport in this cluster (HTTP, OpenAI Responses, Anthropic Messages,
  Azure Foundry, MCP) cascades ``aclose`` into the auth provider — so after
  ``transport.aclose()`` the provider's ``_client.is_closed`` flips to ``True``.
* The cascade also runs when the data-plane close raises (try/finally ordering).
"""

from __future__ import annotations

import httpx
import pytest

from agent_guardian.transports.anthropic_messages import AnthropicMessagesTransport
from agent_guardian.transports.auth.azure_entra import AzureEntraAuth
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.auth.mcp_oauth import McpOAuthProvider
from agent_guardian.transports.auth.oauth2 import OAuth2ClientCredentialsAuth
from agent_guardian.transports.azure_foundry import AzureFoundryAgentTransport
from agent_guardian.transports.http import HttpTransport
from agent_guardian.transports.mcp import McpTransport
from agent_guardian.transports.openai_responses import OpenAiResponsesTransport

TENANT = "00000000-0000-0000-0000-000000000000"
TOKEN_URL = "https://auth.example.com/oauth/token"
RESOURCE = "https://mcp.example.com"
ENTRA_TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"


# --------------------------------------------------------------------------- #
# ABC default + NoAuth
# --------------------------------------------------------------------------- #


async def test_authprovider_default_aclose_is_noop() -> None:
    """A provider that does not override ``aclose`` must succeed silently."""

    class _Custom(AuthProvider):
        async def apply(self, ctx: AuthContext) -> None:
            return None

    auth = _Custom()
    # Idempotent and side-effect-free.
    assert await auth.aclose() is None
    assert await auth.aclose() is None


async def test_noauth_aclose_is_noop() -> None:
    auth = NoAuth()
    assert await auth.aclose() is None


# --------------------------------------------------------------------------- #
# Provider override: closes its injected httpx.AsyncClient
# --------------------------------------------------------------------------- #


async def test_oauth2_aclose_closes_injected_client() -> None:
    client = httpx.AsyncClient()
    auth = OAuth2ClientCredentialsAuth(
        token_url=TOKEN_URL,
        client_id="cid",
        client_secret="cs",
        client=client,
    )
    assert client.is_closed is False
    await auth.aclose()
    assert client.is_closed is True


async def test_azure_entra_aclose_closes_injected_client() -> None:
    client = httpx.AsyncClient()
    auth = AzureEntraAuth(
        tenant_id=TENANT,
        client_id="cid",
        client_secret="cs",
        client=client,
    )
    assert client.is_closed is False
    await auth.aclose()
    assert client.is_closed is True


async def test_mcp_oauth_aclose_closes_injected_client() -> None:
    client = httpx.AsyncClient()
    auth = McpOAuthProvider(
        client_id="cid",
        scopes=[],
        resource=RESOURCE,
        token_url=TOKEN_URL,
        client=client,
    )
    assert client.is_closed is False
    await auth.aclose()
    assert client.is_closed is True


# --------------------------------------------------------------------------- #
# Transport cascade: transport.aclose() closes provider._client too
# --------------------------------------------------------------------------- #


def _make_oauth2_auth() -> tuple[OAuth2ClientCredentialsAuth, httpx.AsyncClient]:
    client = httpx.AsyncClient()
    auth = OAuth2ClientCredentialsAuth(
        token_url=TOKEN_URL, client_id="cid", client_secret="cs", client=client
    )
    return auth, client


async def test_http_transport_aclose_cascades_to_auth() -> None:
    auth, auth_client = _make_oauth2_auth()
    t = HttpTransport(endpoint="https://target.example.com/v1/chat", auth=auth)
    await t.aclose()
    assert auth_client.is_closed is True


async def test_openai_responses_transport_aclose_cascades_to_auth() -> None:
    auth, auth_client = _make_oauth2_auth()
    t = OpenAiResponsesTransport(base_url="https://api.openai.example/v1", auth=auth)
    await t.aclose()
    assert auth_client.is_closed is True


async def test_anthropic_messages_transport_aclose_cascades_to_auth() -> None:
    auth, auth_client = _make_oauth2_auth()
    t = AnthropicMessagesTransport(base_url="https://api.anthropic.example/v1", auth=auth)
    await t.aclose()
    assert auth_client.is_closed is True


async def test_azure_foundry_transport_aclose_cascades_to_auth() -> None:
    auth, auth_client = _make_oauth2_auth()
    t = AzureFoundryAgentTransport(
        endpoint="https://foundry.example.com",
        agent_id="agent-1",
        auth=auth,
    )
    await t.aclose()
    assert auth_client.is_closed is True


async def test_mcp_transport_aclose_cascades_to_auth() -> None:
    auth, auth_client = _make_oauth2_auth()
    t = McpTransport("https://mcp.example.com/mcp", auth=auth)
    await t.aclose()
    assert auth_client.is_closed is True


# --------------------------------------------------------------------------- #
# Cascade still runs when the data-plane close raises (try/finally)
# --------------------------------------------------------------------------- #


class _AdapterRaisesOnClose:
    """Adapter stand-in whose ``aclose`` raises but is irrelevant for ``send``."""

    def __init__(self) -> None:
        self.closed_called = False

    async def aclose(self) -> None:
        self.closed_called = True
        raise RuntimeError("adapter close boom")

    async def send_raw(
        self, body: dict[str, object], headers: dict[str, str]
    ) -> dict[str, object]:  # pragma: no cover - not exercised
        return {}


async def test_http_transport_aclose_cascades_to_auth_even_when_adapter_raises() -> None:
    auth, auth_client = _make_oauth2_auth()
    t = HttpTransport(endpoint="https://target.example.com/v1/chat", auth=auth)
    # Force the transport to own a misbehaving adapter so the ``finally`` arm
    # runs the auth-provider close regardless.
    bad = _AdapterRaisesOnClose()
    t._owns_adapter = True
    t._adapter = bad  # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="adapter close boom"):
        await t.aclose()
    assert bad.closed_called is True
    # Even though the adapter close raised, the auth provider was still closed.
    assert auth_client.is_closed is True


async def test_mcp_transport_aclose_cascades_to_auth_even_when_client_raises() -> None:
    auth, auth_client = _make_oauth2_auth()
    t = McpTransport("https://mcp.example.com/mcp", auth=auth)

    class _BadClient:
        def __init__(self) -> None:
            self.closed_called = False

        async def aclose(self) -> None:
            self.closed_called = True
            raise RuntimeError("client close boom")

    bad = _BadClient()
    t._owns_client = True
    t._client = bad  # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="client close boom"):
        await t.aclose()
    assert bad.closed_called is True
    assert auth_client.is_closed is True
