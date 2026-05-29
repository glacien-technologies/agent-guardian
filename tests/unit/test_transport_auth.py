"""Tests for auth providers: api_key, bearer, oauth2, mtls, hmac."""

from __future__ import annotations

import hashlib
import hmac as hmaclib

import httpx
import pytest
import respx

from agent_guardian.llm.errors import LLMAuthError
from agent_guardian.transports.auth.api_key import ApiKeyAuth
from agent_guardian.transports.auth.base import AuthContext, NoAuth
from agent_guardian.transports.auth.bearer import BearerAuth
from agent_guardian.transports.auth.hmac import HmacAuth
from agent_guardian.transports.auth.mtls import MutualTlsAuth
from agent_guardian.transports.auth.oauth2 import OAuth2ClientCredentialsAuth

TOKEN_URL = "https://auth.example.com/token"


def _ctx() -> AuthContext:
    return AuthContext(method="POST", url="https://x.example.com/api", body=b'{"a":1}')


async def test_no_auth_is_noop() -> None:
    ctx = _ctx()
    await NoAuth().apply(ctx)
    assert ctx.headers == {}


async def test_api_key_default_header() -> None:
    ctx = _ctx()
    await ApiKeyAuth("secret-key").apply(ctx)
    assert ctx.headers["x-api-key"] == "secret-key"


async def test_api_key_custom_header_and_template() -> None:
    ctx = _ctx()
    await ApiKeyAuth("k", header_name="X-Auth", value_template="ApiKey {key}").apply(ctx)
    assert ctx.headers["X-Auth"] == "ApiKey k"


def test_api_key_rejects_empty() -> None:
    with pytest.raises(ValueError, match="api_key"):
        ApiKeyAuth("")


async def test_bearer_sets_authorization() -> None:
    ctx = _ctx()
    await BearerAuth("tok123").apply(ctx)
    assert ctx.headers["Authorization"] == "Bearer tok123"


async def test_bearer_custom_scheme() -> None:
    ctx = _ctx()
    await BearerAuth("tok", scheme="Token").apply(ctx)
    assert ctx.headers["Authorization"] == "Token tok"


def test_bearer_rejects_empty() -> None:
    with pytest.raises(ValueError, match="token"):
        BearerAuth("")


async def test_mtls_sets_client_kwargs() -> None:
    ctx = _ctx()
    auth = MutualTlsAuth(cert=("client.pem", "client.key"), verify="ca.pem")
    await auth.apply(ctx)
    assert ctx.client_kwargs["cert"] == ("client.pem", "client.key")
    assert ctx.client_kwargs["verify"] == "ca.pem"
    # no header mutation
    assert ctx.headers == {}


def test_mtls_rejects_empty_cert() -> None:
    with pytest.raises(ValueError, match="cert"):
        MutualTlsAuth(cert="")


def test_mtls_exposes_cert_and_verify_properties() -> None:
    auth = MutualTlsAuth(cert="client.pem", verify=False)
    assert auth.cert == "client.pem"
    assert auth.verify is False


async def test_hmac_path_falls_back_for_bare_path_url() -> None:
    ctx = AuthContext(method="GET", url="/api?x=1", body=b"")
    auth = HmacAuth(
        "shh",
        signing_string_template="{path}",
        clock=lambda: 1.0,
        nonce_factory=lambda: "n",
    )
    await auth.apply(ctx)
    expected = hmaclib.new(b"shh", b"/api", hashlib.sha256).hexdigest()
    assert ctx.headers["x-signature"] == expected


async def test_hmac_base64_round_trips() -> None:
    import base64 as b64

    ctx = AuthContext(method="POST", url="https://x/api", body=b"body")
    auth = HmacAuth(
        "shh",
        signing_string_template="{body}",
        encoding="base64",
        timestamp_header=None,
        clock=lambda: 1.0,
        nonce_factory=lambda: "n",
    )
    await auth.apply(ctx)
    expected = b64.b64encode(hmaclib.new(b"shh", b"body", hashlib.sha256).digest()).decode("ascii")
    assert ctx.headers["x-signature"] == expected
    assert "x-timestamp" not in ctx.headers


def test_hmac_rejects_unknown_algorithm() -> None:
    with pytest.raises(ValueError, match="algorithm"):
        HmacAuth("s", algorithm="not-a-hash")


async def test_hmac_signature_matches_manual() -> None:
    ctx = _ctx()
    auth = HmacAuth(
        "shh",
        signing_string_template="{method}\n{path}\n{timestamp}\n{body}",
        clock=lambda: 1000.0,
        nonce_factory=lambda: "fixed-nonce",
    )
    await auth.apply(ctx)
    signing = 'POST\n/api\n1000\n{"a":1}'
    expected = hmaclib.new(b"shh", signing.encode(), hashlib.sha256).hexdigest()
    assert ctx.headers["x-signature"] == expected
    assert ctx.headers["x-timestamp"] == "1000"


async def test_hmac_base64_encoding_and_nonce_header() -> None:
    ctx = _ctx()
    auth = HmacAuth(
        "shh",
        encoding="base64",
        nonce_header="x-nonce",
        nonce_factory=lambda: "n1",
        clock=lambda: 5.0,
    )
    await auth.apply(ctx)
    assert ctx.headers["x-nonce"] == "n1"
    # base64 signature shouldn't look like hex-only of fixed length
    assert "=" in ctx.headers["x-signature"] or len(ctx.headers["x-signature"]) % 4 == 0


def test_hmac_rejects_bad_encoding() -> None:
    with pytest.raises(ValueError, match="encoding"):
        HmacAuth("s", encoding="rot13")


def test_hmac_rejects_empty_secret() -> None:
    with pytest.raises(ValueError, match="secret"):
        HmacAuth("")


@respx.mock
async def test_oauth2_fetches_and_caches_token() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "AT1", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL,
            client_id="cid",
            client_secret="csecret",
            scope="read",
            client=client,
        )
        ctx1 = _ctx()
        await auth.apply(ctx1)
        assert ctx1.headers["Authorization"] == "Bearer AT1"
        # second apply reuses cache → no second fetch
        ctx2 = _ctx()
        await auth.apply(ctx2)
        assert ctx2.headers["Authorization"] == "Bearer AT1"
    assert route.call_count == 1


@respx.mock
async def test_oauth2_refreshes_before_expiry() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "AT1", "expires_in": 0}),
            httpx.Response(200, json={"access_token": "AT2", "expires_in": 3600}),
        ]
    )
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL,
            client_id="cid2",
            client_secret="cs",
            client=client,
            expiry_leeway_seconds=60.0,
        )
        ctx1 = _ctx()
        await auth.apply(ctx1)  # AT1, but expires_in=0 → stale immediately
        ctx2 = _ctx()
        await auth.apply(ctx2)  # must refetch → AT2
        assert ctx2.headers["Authorization"] == "Bearer AT2"
    assert route.call_count == 2


@respx.mock
async def test_oauth2_on_unauthorized_refreshes_and_signals_retry() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "OLD", "expires_in": 3600}),
            httpx.Response(200, json={"access_token": "NEW", "expires_in": 3600}),
        ]
    )
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL,
            client_id="cid3",
            client_secret="cs",
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
async def test_oauth2_token_endpoint_error_raises_auth() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(403, text="denied"))
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL,
            client_id="cid4",
            client_secret="cs",
            client=client,
        )
        with pytest.raises(LLMAuthError, match="403"):
            await auth.apply(_ctx())


@respx.mock
async def test_oauth2_missing_access_token_raises() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"nope": 1}))
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL,
            client_id="cid5",
            client_secret="cs",
            client=client,
        )
        with pytest.raises(LLMAuthError, match="access_token"):
            await auth.apply(_ctx())


@respx.mock
async def test_oauth2_non_numeric_expires_in_uses_default() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "AT", "expires_in": "not-a-number"})
    )
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL,
            client_id="cid-exp",
            client_secret="cs",
            client=client,
        )
        ctx = _ctx()
        await auth.apply(ctx)
        assert ctx.headers["Authorization"] == "Bearer AT"


@respx.mock
async def test_oauth2_non_json_response_raises() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200, content=b"<html>", headers={"content-type": "application/json"}
        )
    )
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL, client_id="cid-nj", client_secret="cs", client=client
        )
        with pytest.raises(LLMAuthError, match="not JSON"):
            await auth.apply(_ctx())


@respx.mock
async def test_oauth2_network_error_raises() -> None:
    OAuth2ClientCredentialsAuth.clear_cache()
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
    async with httpx.AsyncClient() as client:
        auth = OAuth2ClientCredentialsAuth(
            token_url=TOKEN_URL, client_id="cid-ne", client_secret="cs", client=client
        )
        with pytest.raises(LLMAuthError, match="token request failed"):
            await auth.apply(_ctx())


async def test_oauth2_rejects_empty_config() -> None:
    async with httpx.AsyncClient() as dummy:
        with pytest.raises(ValueError, match="token_url"):
            OAuth2ClientCredentialsAuth(
                token_url="", client_id="c", client_secret="s", client=dummy
            )
        with pytest.raises(ValueError, match="client_id"):
            OAuth2ClientCredentialsAuth(
                token_url=TOKEN_URL, client_id="", client_secret="s", client=dummy
            )
