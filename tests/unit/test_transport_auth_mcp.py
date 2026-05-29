"""Tests for the MCP OAuth 2.1 + PKCE (S256) auth provider with RFC 9728 discovery."""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest
import respx

from agent_guardian.llm.errors import LLMAuthError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider
from agent_guardian.transports.auth.mcp_oauth import (
    McpOAuthProvider,
    PkcePair,
    compute_pkce,
)

RESOURCE = "https://mcp.example.com"
AUTH_SERVER = "https://auth.example.com"
PRM_URL = "https://mcp.example.com/.well-known/oauth-protected-resource"
ASM_URL = "https://auth.example.com/.well-known/oauth-authorization-server"
TOKEN_URL = "https://auth.example.com/oauth/token"
AUTHZ_URL = "https://auth.example.com/oauth/authorize"


def _ctx(url: str = "https://mcp.example.com/mcp") -> AuthContext:
    return AuthContext(method="POST", url=url, body=b'{"jsonrpc":"2.0"}')


# --------------------------------------------------------------------------- #
# PKCE (S256)
# --------------------------------------------------------------------------- #


def test_compute_pkce_is_valid_s256_challenge() -> None:
    pair = compute_pkce()
    assert isinstance(pair, PkcePair)
    # challenge == base64url(sha256(verifier)) with no padding.
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(pair.verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert pair.challenge == expected
    assert "=" not in pair.challenge
    assert "=" not in pair.verifier
    # RFC 7636 verifier length window.
    assert 43 <= len(pair.verifier) <= 128


def test_compute_pkce_accepts_explicit_verifier() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    pair = compute_pkce(verifier=verifier)
    assert pair.verifier == verifier
    # RFC 7636 worked example.
    assert pair.challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_compute_pkce_is_high_entropy_and_unique() -> None:
    a = compute_pkce()
    b = compute_pkce()
    assert a.verifier != b.verifier
    assert a.challenge != b.challenge


async def test_provider_exposes_pkce_material() -> None:
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid",
            scopes=["a", "b"],
            resource=RESOURCE,
            token_url=TOKEN_URL,
            client=client,
        )
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(auth.code_verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        assert auth.code_challenge == expected
        assert auth.code_challenge_method == "S256"
        assert auth.scope == "a b"


# --------------------------------------------------------------------------- #
# RFC 9728 discovery
# --------------------------------------------------------------------------- #


@respx.mock
async def test_discovery_chains_prm_to_asm_to_token_endpoint() -> None:
    McpOAuthProvider.clear_cache()
    prm = respx.get(PRM_URL).mock(
        return_value=httpx.Response(200, json={"authorization_servers": [AUTH_SERVER]})
    )
    asm = respx.get(ASM_URL).mock(
        return_value=httpx.Response(
            200,
            json={"token_endpoint": TOKEN_URL, "authorization_endpoint": AUTHZ_URL},
        )
    )
    token = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "DISCOVERED", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid",
            client_secret="secret",
            scopes=["mcp.read"],
            resource=RESOURCE,
            token_url=None,
            client=client,
        )
        ctx = _ctx()
        await auth.apply(ctx)
        assert ctx.headers["Authorization"] == "Bearer DISCOVERED"
    assert prm.called and asm.called and token.called
    assert prm.call_count == 1
    assert asm.call_count == 1


@respx.mock
async def test_discovery_is_cached_across_requests() -> None:
    McpOAuthProvider.clear_cache()
    prm = respx.get(PRM_URL).mock(
        return_value=httpx.Response(200, json={"authorization_servers": [AUTH_SERVER]})
    )
    asm = respx.get(ASM_URL).mock(
        return_value=httpx.Response(200, json={"token_endpoint": TOKEN_URL})
    )
    respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "T1", "expires_in": 0}),
            httpx.Response(200, json={"access_token": "T2", "expires_in": 3600}),
        ]
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-cache",
            scopes=[],
            resource=RESOURCE,
            token_url=None,
            client=client,
        )
        await auth.apply(_ctx())
        ctx2 = _ctx()
        await auth.apply(ctx2)
        assert ctx2.headers["Authorization"] == "Bearer T2"
    # Discovery happens once; the token endpoint is re-hit on the expired token.
    assert prm.call_count == 1
    assert asm.call_count == 1


@respx.mock
async def test_discovery_uses_origin_well_known_ignoring_resource_path() -> None:
    McpOAuthProvider.clear_cache()
    prm = respx.get(PRM_URL).mock(
        return_value=httpx.Response(200, json={"authorization_servers": [AUTH_SERVER]})
    )
    respx.get(ASM_URL).mock(return_value=httpx.Response(200, json={"token_endpoint": TOKEN_URL}))
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "OK", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-path",
            scopes=[],
            resource="https://mcp.example.com/some/mcp/path",
            token_url=None,
            client=client,
        )
        await auth.apply(_ctx())
    assert prm.called


@respx.mock
async def test_discovery_missing_authorization_servers_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.get(PRM_URL).mock(return_value=httpx.Response(200, json={"nope": 1}))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-x", scopes=[], resource=RESOURCE, token_url=None, client=client
        )
        with pytest.raises(LLMAuthError, match="authorization_servers"):
            await auth.apply(_ctx())


@respx.mock
async def test_discovery_non_string_auth_server_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.get(PRM_URL).mock(return_value=httpx.Response(200, json={"authorization_servers": [123]}))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-y", scopes=[], resource=RESOURCE, token_url=None, client=client
        )
        with pytest.raises(LLMAuthError, match="URL string"):
            await auth.apply(_ctx())


@respx.mock
async def test_discovery_missing_token_endpoint_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.get(PRM_URL).mock(
        return_value=httpx.Response(200, json={"authorization_servers": [AUTH_SERVER]})
    )
    respx.get(ASM_URL).mock(return_value=httpx.Response(200, json={"issuer": AUTH_SERVER}))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-z", scopes=[], resource=RESOURCE, token_url=None, client=client
        )
        with pytest.raises(LLMAuthError, match="token_endpoint"):
            await auth.apply(_ctx())


@respx.mock
async def test_discovery_http_error_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.get(PRM_URL).mock(return_value=httpx.Response(404, text="nope"))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-404", scopes=[], resource=RESOURCE, token_url=None, client=client
        )
        with pytest.raises(LLMAuthError, match="404"):
            await auth.apply(_ctx())


@respx.mock
async def test_discovery_network_error_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.get(PRM_URL).mock(side_effect=httpx.ConnectError("down"))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-ne", scopes=[], resource=RESOURCE, token_url=None, client=client
        )
        with pytest.raises(LLMAuthError, match="request failed"):
            await auth.apply(_ctx())


@respx.mock
async def test_discovery_non_json_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.get(PRM_URL).mock(
        return_value=httpx.Response(
            200, content=b"<html>", headers={"content-type": "application/json"}
        )
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-nj", scopes=[], resource=RESOURCE, token_url=None, client=client
        )
        with pytest.raises(LLMAuthError, match="not JSON"):
            await auth.apply(_ctx())


@respx.mock
async def test_discovery_non_object_json_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.get(PRM_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-arr", scopes=[], resource=RESOURCE, token_url=None, client=client
        )
        with pytest.raises(LLMAuthError, match="JSON object"):
            await auth.apply(_ctx())


# --------------------------------------------------------------------------- #
# Token acquisition / caching / refresh
# --------------------------------------------------------------------------- #


@respx.mock
async def test_token_fetched_and_cached() -> None:
    McpOAuthProvider.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "TOK1", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-tok",
            client_secret="sec",
            scopes=["mcp.read", "mcp.write"],
            resource=RESOURCE,
            token_url=TOKEN_URL,
            client=client,
        )
        ctx1 = _ctx()
        await auth.apply(ctx1)
        assert ctx1.headers["Authorization"] == "Bearer TOK1"
        ctx2 = _ctx()
        await auth.apply(ctx2)
        assert ctx2.headers["Authorization"] == "Bearer TOK1"
    assert route.call_count == 1


@respx.mock
async def test_token_request_carries_pkce_and_client_credentials() -> None:
    McpOAuthProvider.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "X", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-body",
            client_secret="shh",
            scopes=["mcp.read"],
            resource=RESOURCE,
            token_url=TOKEN_URL,
            client=client,
        )
        await auth.apply(_ctx())
    body = bytes(route.calls.last.request.content).decode()
    assert "grant_type=client_credentials" in body
    assert "client_id=cid-body" in body
    assert "client_secret=shh" in body
    assert "code_challenge_method=S256" in body
    assert f"code_challenge={auth.code_challenge}" in body
    assert "scope=mcp.read" in body


@respx.mock
async def test_token_request_omits_secret_for_public_client() -> None:
    McpOAuthProvider.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "X", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="public-cid",
            scopes=[],
            resource=None,
            token_url=TOKEN_URL,
            client=client,
        )
        await auth.apply(_ctx())
    body = bytes(route.calls.last.request.content).decode()
    assert "client_secret" not in body
    assert "scope=" not in body
    assert "resource=" not in body


@respx.mock
async def test_on_unauthorized_refreshes_and_signals_retry() -> None:
    McpOAuthProvider.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "OLD", "expires_in": 3600}),
            httpx.Response(200, json={"access_token": "NEW", "expires_in": 3600}),
        ]
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-401",
            scopes=[],
            resource=RESOURCE,
            token_url=TOKEN_URL,
            client=client,
        )
        ctx = _ctx()
        await auth.apply(ctx)
        assert ctx.headers["Authorization"] == "Bearer OLD"
        retry = await auth.on_unauthorized(ctx)
        assert retry is True
        assert ctx.headers["Authorization"] == "Bearer NEW"
    assert route.call_count == 2


@respx.mock
async def test_refreshes_before_expiry() -> None:
    McpOAuthProvider.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "AT1", "expires_in": 0}),
            httpx.Response(200, json={"access_token": "AT2", "expires_in": 3600}),
        ]
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-exp",
            scopes=[],
            resource=RESOURCE,
            token_url=TOKEN_URL,
            client=client,
        )
        await auth.apply(_ctx())
        ctx2 = _ctx()
        await auth.apply(ctx2)
        assert ctx2.headers["Authorization"] == "Bearer AT2"
    assert route.call_count == 2


@respx.mock
async def test_token_endpoint_error_raises_auth() -> None:
    McpOAuthProvider.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401, text="denied"))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-te", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        with pytest.raises(LLMAuthError, match="401"):
            await auth.apply(_ctx())


@respx.mock
async def test_token_missing_access_token_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"nope": 1}))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-ma", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        with pytest.raises(LLMAuthError, match="access_token"):
            await auth.apply(_ctx())


@respx.mock
async def test_token_non_numeric_expires_in_uses_default() -> None:
    McpOAuthProvider.clear_cache()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "AT", "expires_in": "nope"})
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-ne2", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        ctx = _ctx()
        await auth.apply(ctx)
        assert ctx.headers["Authorization"] == "Bearer AT"


@respx.mock
async def test_token_network_error_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-tn", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        with pytest.raises(LLMAuthError, match="token request failed"):
            await auth.apply(_ctx())


@respx.mock
async def test_token_non_json_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200, content=b"<html>", headers={"content-type": "application/json"}
        )
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-tnj", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        with pytest.raises(LLMAuthError, match="not JSON"):
            await auth.apply(_ctx())


@respx.mock
async def test_token_non_object_json_raises() -> None:
    McpOAuthProvider.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-toj", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        with pytest.raises(LLMAuthError, match="JSON object"):
            await auth.apply(_ctx())


# --------------------------------------------------------------------------- #
# Bearer token never in a query string
# --------------------------------------------------------------------------- #


@respx.mock
async def test_apply_never_puts_token_in_query_string() -> None:
    McpOAuthProvider.clear_cache()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "SECRETTOKEN", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-q", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        ctx = _ctx(url="https://mcp.example.com/mcp?foo=bar")
        await auth.apply(ctx)
        # Token lives only in the Authorization header.
        assert ctx.headers["Authorization"] == "Bearer SECRETTOKEN"
        # URL is untouched and never carries the token.
        assert ctx.url == "https://mcp.example.com/mcp?foo=bar"
        assert "SECRETTOKEN" not in ctx.url
        assert "access_token" not in ctx.url


async def test_apply_asserts_on_token_in_query_string() -> None:
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid-assert",
            scopes=[],
            resource=RESOURCE,
            token_url=TOKEN_URL,
            client=client,
        )
        ctx = _ctx(url="https://mcp.example.com/mcp?access_token=leaked")
        with pytest.raises(AssertionError, match="query string"):
            await auth.apply(ctx)


# --------------------------------------------------------------------------- #
# Construction / interface
# --------------------------------------------------------------------------- #


async def test_rejects_empty_client_id() -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="client_id"):
            McpOAuthProvider(
                client_id="", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
            )


async def test_rejects_no_token_url_and_no_resource() -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="token_url or a resource"):
            McpOAuthProvider(
                client_id="cid", scopes=[], resource=None, token_url=None, client=client
            )


async def test_is_auth_provider() -> None:
    async with httpx.AsyncClient() as client:
        auth = McpOAuthProvider(
            client_id="cid", scopes=[], resource=RESOURCE, token_url=TOKEN_URL, client=client
        )
        assert isinstance(auth, AuthProvider)
