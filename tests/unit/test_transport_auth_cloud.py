"""Tests for the cloud auth providers: AWS SigV4, Azure Entra, GCP ADC/SA-JSON."""

from __future__ import annotations

import builtins
import json
from typing import Any

import httpx
import pytest
import respx

from agent_guardian.llm.errors import LLMAuthError
from agent_guardian.transports.auth.azure_entra import AzureEntraAuth
from agent_guardian.transports.auth.base import AuthContext, AuthProvider
from agent_guardian.transports.auth.gcp import GcpAdcAuth, GcpSaJsonAuth
from agent_guardian.transports.auth.sigv4 import AwsSigV4Auth


def _ctx() -> AuthContext:
    return AuthContext(
        method="POST",
        url="https://bedrock-runtime.us-east-1.amazonaws.com/model/foo/invoke",
        body=b'{"a":1}',
    )


# --------------------------------------------------------------------------- #
# AWS SigV4
# --------------------------------------------------------------------------- #


async def test_sigv4_signs_with_explicit_credentials() -> None:
    pytest.importorskip("botocore")
    auth = AwsSigV4Auth(
        region="us-east-1",
        service="bedrock",
        access_key_id="AKIDEXAMPLE",
        secret_access_key="SECRETEXAMPLE",
    )
    ctx = _ctx()
    await auth.apply(ctx)
    assert "AWS4-HMAC-SHA256" in ctx.headers["Authorization"]
    assert "Credential=AKIDEXAMPLE/" in ctx.headers["Authorization"]
    assert "us-east-1/bedrock/aws4_request" in ctx.headers["Authorization"]
    assert "X-Amz-Date" in ctx.headers
    # no session token supplied → no security-token header
    assert "X-Amz-Security-Token" not in ctx.headers


async def test_sigv4_includes_session_token_header() -> None:
    pytest.importorskip("botocore")
    auth = AwsSigV4Auth(
        region="eu-west-1",
        service="bedrock",
        access_key_id="AKID",
        secret_access_key="SECRET",
        session_token="SESSIONTOKEN",
    )
    ctx = _ctx()
    await auth.apply(ctx)
    assert ctx.headers["X-Amz-Security-Token"] == "SESSIONTOKEN"
    assert "AWS4-HMAC-SHA256" in ctx.headers["Authorization"]


async def test_sigv4_falls_back_to_default_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("botocore")
    import botocore.credentials
    import botocore.session

    fake = botocore.credentials.Credentials(access_key="CHAINKEY", secret_key="CHAINSECRET")
    monkeypatch.setattr(
        botocore.session.Session, "get_credentials", lambda self: fake, raising=True
    )
    auth = AwsSigV4Auth(region="us-east-1", service="bedrock")
    ctx = _ctx()
    await auth.apply(ctx)
    assert "Credential=CHAINKEY/" in ctx.headers["Authorization"]


async def test_sigv4_raises_when_default_chain_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("botocore")
    import botocore.session

    monkeypatch.setattr(
        botocore.session.Session, "get_credentials", lambda self: None, raising=True
    )
    auth = AwsSigV4Auth(region="us-east-1", service="bedrock")
    with pytest.raises(ValueError, match="no AWS credentials"):
        await auth.apply(_ctx())


def test_sigv4_rejects_empty_region_and_service() -> None:
    pytest.importorskip("botocore")
    with pytest.raises(ValueError, match="region"):
        AwsSigV4Auth(region="", service="bedrock")
    with pytest.raises(ValueError, match="service"):
        AwsSigV4Auth(region="us-east-1", service="")


def test_sigv4_raises_clear_import_error_when_botocore_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def _blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("botocore"):
            raise ImportError("no botocore")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    with pytest.raises(ImportError, match=r"agent-guardian\[aws\]"):
        AwsSigV4Auth(region="us-east-1", service="bedrock")


def test_sigv4_is_auth_provider() -> None:
    pytest.importorskip("botocore")
    assert isinstance(
        AwsSigV4Auth(
            region="us-east-1", service="bedrock", access_key_id="a", secret_access_key="b"
        ),
        AuthProvider,
    )


# --------------------------------------------------------------------------- #
# Azure Entra ID
# --------------------------------------------------------------------------- #

TENANT = "00000000-0000-0000-0000-000000000000"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"


@respx.mock
async def test_azure_entra_fetches_and_caches_token() -> None:
    AzureEntraAuth.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "ENTRA1", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(
            tenant_id=TENANT,
            client_id="app-id",
            client_secret="app-secret",
            scope="https://example.com/.default",
            client=client,
        )
        ctx1 = _ctx()
        await auth.apply(ctx1)
        assert ctx1.headers["Authorization"] == "Bearer ENTRA1"
        ctx2 = _ctx()
        await auth.apply(ctx2)
        assert ctx2.headers["Authorization"] == "Bearer ENTRA1"
    assert route.call_count == 1


@respx.mock
async def test_azure_entra_token_url_is_v2_endpoint() -> None:
    AzureEntraAuth.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "X", "expires_in": 3600})
    )
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(tenant_id=TENANT, client_id="cid", client_secret="cs", client=client)
        await auth.apply(_ctx())
    assert route.called
    request = route.calls.last.request
    assert str(request.url) == TOKEN_URL
    body = bytes(request.content).decode()
    assert "grant_type=client_credentials" in body
    assert "scope=" in body


@respx.mock
async def test_azure_entra_on_unauthorized_refreshes_and_signals_retry() -> None:
    AzureEntraAuth.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "OLD", "expires_in": 3600}),
            httpx.Response(200, json={"access_token": "NEW", "expires_in": 3600}),
        ]
    )
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(tenant_id=TENANT, client_id="cid2", client_secret="cs", client=client)
        ctx = _ctx()
        await auth.apply(ctx)
        assert ctx.headers["Authorization"] == "Bearer OLD"
        retry = await auth.on_unauthorized(ctx)
        assert retry is True
        assert ctx.headers["Authorization"] == "Bearer NEW"
    assert route.call_count == 2


@respx.mock
async def test_azure_entra_refreshes_before_expiry() -> None:
    AzureEntraAuth.clear_cache()
    route = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "AT1", "expires_in": 0}),
            httpx.Response(200, json={"access_token": "AT2", "expires_in": 3600}),
        ]
    )
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(tenant_id=TENANT, client_id="cid3", client_secret="cs", client=client)
        await auth.apply(_ctx())
        ctx2 = _ctx()
        await auth.apply(ctx2)
        assert ctx2.headers["Authorization"] == "Bearer AT2"
    assert route.call_count == 2


@respx.mock
async def test_azure_entra_token_endpoint_error_raises_auth() -> None:
    AzureEntraAuth.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401, text="denied"))
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(tenant_id=TENANT, client_id="cid4", client_secret="cs", client=client)
        with pytest.raises(LLMAuthError, match="401"):
            await auth.apply(_ctx())


@respx.mock
async def test_azure_entra_missing_access_token_raises() -> None:
    AzureEntraAuth.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"nope": 1}))
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(tenant_id=TENANT, client_id="cid5", client_secret="cs", client=client)
        with pytest.raises(LLMAuthError, match="access_token"):
            await auth.apply(_ctx())


@respx.mock
async def test_azure_entra_non_numeric_expires_in_uses_default() -> None:
    AzureEntraAuth.clear_cache()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "AT", "expires_in": "nope"})
    )
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(
            tenant_id=TENANT, client_id="cid-exp", client_secret="cs", client=client
        )
        ctx = _ctx()
        await auth.apply(ctx)
        assert ctx.headers["Authorization"] == "Bearer AT"


@respx.mock
async def test_azure_entra_network_error_raises() -> None:
    AzureEntraAuth.clear_cache()
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(
            tenant_id=TENANT, client_id="cid-ne", client_secret="cs", client=client
        )
        with pytest.raises(LLMAuthError, match="token request failed"):
            await auth.apply(_ctx())


@respx.mock
async def test_azure_entra_non_json_response_raises() -> None:
    AzureEntraAuth.clear_cache()
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200, content=b"<html>", headers={"content-type": "application/json"}
        )
    )
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(
            tenant_id=TENANT, client_id="cid-nj", client_secret="cs", client=client
        )
        with pytest.raises(LLMAuthError, match="not JSON"):
            await auth.apply(_ctx())


@respx.mock
async def test_azure_entra_non_object_json_raises() -> None:
    AzureEntraAuth.clear_cache()
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    async with httpx.AsyncClient() as client:
        auth = AzureEntraAuth(
            tenant_id=TENANT, client_id="cid-arr", client_secret="cs", client=client
        )
        with pytest.raises(LLMAuthError, match="JSON object"):
            await auth.apply(_ctx())


async def test_azure_entra_rejects_empty_config() -> None:
    async with httpx.AsyncClient() as dummy:
        with pytest.raises(ValueError, match="tenant_id"):
            AzureEntraAuth(tenant_id="", client_id="c", client_secret="s", client=dummy)
        with pytest.raises(ValueError, match="client_id"):
            AzureEntraAuth(tenant_id=TENANT, client_id="", client_secret="s", client=dummy)
        with pytest.raises(ValueError, match="scope"):
            AzureEntraAuth(
                tenant_id=TENANT, client_id="c", client_secret="s", scope="", client=dummy
            )


async def test_azure_entra_is_auth_provider() -> None:
    async with httpx.AsyncClient() as dummy:
        auth = AzureEntraAuth(tenant_id=TENANT, client_id="c", client_secret="s", client=dummy)
        assert isinstance(auth, AuthProvider)


# --------------------------------------------------------------------------- #
# GCP — ADC and service-account JSON
# --------------------------------------------------------------------------- #


class _FakeCreds:
    """Minimal stand-in for a google.auth Credentials object."""

    def __init__(self, token: str = "GTOKEN") -> None:
        self.token = token
        self.valid = True
        self.refresh_calls = 0

    def refresh(self, request: Any) -> None:
        self.refresh_calls += 1
        self.token = f"REFRESHED{self.refresh_calls}"
        self.valid = True


def _block_imports(monkeypatch: pytest.MonkeyPatch, *prefixes: str) -> None:
    real_import = builtins.__import__

    def _blocked(name: str, *args: Any, **kwargs: Any) -> Any:
        if any(name == p or name.startswith(p + ".") for p in prefixes):
            raise ImportError(f"no {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked)


def test_gcp_adc_raises_clear_import_error_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _block_imports(monkeypatch, "google.auth", "google")
    with pytest.raises(ImportError, match="google-auth"):
        GcpAdcAuth()


def test_gcp_sa_json_raises_clear_import_error_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _block_imports(monkeypatch, "google.oauth2", "google")
    with pytest.raises(ImportError, match="google-auth"):
        GcpSaJsonAuth(service_account_json='{"type": "service_account"}')


def test_gcp_sa_json_rejects_empty() -> None:
    pytest.importorskip("google.auth")
    with pytest.raises(ValueError, match="service_account_json"):
        GcpSaJsonAuth(service_account_json="")


def test_gcp_sa_json_rejects_invalid_json() -> None:
    pytest.importorskip("google.auth")
    with pytest.raises(ValueError, match="not valid JSON"):
        GcpSaJsonAuth(service_account_json="{not json}")


def test_gcp_sa_json_rejects_non_object_json() -> None:
    pytest.importorskip("google.auth")
    with pytest.raises(ValueError, match="JSON object"):
        GcpSaJsonAuth(service_account_json="[1, 2, 3]")


async def test_gcp_adc_mints_token_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.auth")
    import google.auth

    fake = _FakeCreds("ADCTOKEN")
    monkeypatch.setattr(google.auth, "default", lambda scopes=None: (fake, "proj"), raising=True)
    auth = GcpAdcAuth()
    ctx = _ctx()
    await auth.apply(ctx)
    assert ctx.headers["Authorization"] == "Bearer ADCTOKEN"


async def test_gcp_adc_refreshes_when_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.auth")
    import google.auth
    import google.auth.transport.requests as greq

    fake = _FakeCreds("STALE")
    fake.valid = False
    monkeypatch.setattr(google.auth, "default", lambda scopes=None: (fake, None), raising=True)
    monkeypatch.setattr(greq, "Request", lambda *a, **k: object(), raising=True)
    auth = GcpAdcAuth()
    ctx = _ctx()
    await auth.apply(ctx)
    assert fake.refresh_calls == 1
    assert ctx.headers["Authorization"] == "Bearer REFRESHED1"


async def test_gcp_adc_on_unauthorized_force_refreshes(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.auth")
    import google.auth
    import google.auth.transport.requests as greq

    fake = _FakeCreds("OLD")
    monkeypatch.setattr(google.auth, "default", lambda scopes=None: (fake, None), raising=True)
    monkeypatch.setattr(greq, "Request", lambda *a, **k: object(), raising=True)
    auth = GcpAdcAuth()
    ctx = _ctx()
    await auth.apply(ctx)
    assert ctx.headers["Authorization"] == "Bearer OLD"
    retry = await auth.on_unauthorized(ctx)
    assert retry is True
    assert fake.refresh_calls == 1
    assert ctx.headers["Authorization"] == "Bearer REFRESHED1"


async def test_gcp_adc_raises_when_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.auth")
    import google.auth
    import google.auth.transport.requests as greq

    class _NoTokenCreds:
        token = None
        valid = True

        def refresh(self, request: Any) -> None:  # pragma: no cover - not reached
            return None

    monkeypatch.setattr(
        google.auth, "default", lambda scopes=None: (_NoTokenCreds(), None), raising=True
    )
    monkeypatch.setattr(greq, "Request", lambda *a, **k: object(), raising=True)
    auth = GcpAdcAuth()
    with pytest.raises(ValueError, match="access token"):
        await auth.apply(_ctx())


async def test_gcp_sa_json_mints_token_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.auth")
    from google.oauth2 import service_account

    fake = _FakeCreds("SATOKEN")
    monkeypatch.setattr(
        service_account.Credentials,
        "from_service_account_info",
        classmethod(lambda cls, info, scopes=None: fake),
        raising=True,
    )
    payload = json.dumps({"type": "service_account", "client_email": "x@y.iam"})
    auth = GcpSaJsonAuth(service_account_json=payload)
    ctx = _ctx()
    await auth.apply(ctx)
    assert ctx.headers["Authorization"] == "Bearer SATOKEN"


async def test_gcp_sa_json_is_auth_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("google.auth")
    from google.oauth2 import service_account

    monkeypatch.setattr(
        service_account.Credentials,
        "from_service_account_info",
        classmethod(lambda cls, info, scopes=None: _FakeCreds()),
        raising=True,
    )
    auth = GcpSaJsonAuth(service_account_json='{"type": "service_account"}')
    assert isinstance(auth, AuthProvider)
