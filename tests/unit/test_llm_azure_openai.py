"""Tests for AzureOpenAIClient (api-key mode + optional Entra)."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from agent_guardian.llm.azure_openai import AzureOpenAIClient
from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import LLMAuthError

_ENDPOINT = "https://my-resource.openai.azure.com"


def _req() -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="ignored")


def _ok_body() -> dict[str, object]:
    return {
        "choices": [{"message": {"content": "ack"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
        "model": "gpt-4o",
    }


def _deployment_url(deployment: str, api_version: str) -> str:
    return f"{_ENDPOINT}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"


@respx.mock
async def test_azure_exact_deployment_url_and_api_key_header() -> None:
    """Reviewer correction #2 — STANDARD deployment path + api-version, api-key
    header (NOT Authorization: Bearer)."""
    url = _deployment_url("my-gpt4o-deployment", "2024-10-21")
    route = respx.post(url).mock(return_value=Response(200, json=_ok_body()))
    llm = AzureOpenAIClient(deployment="my-gpt4o-deployment", endpoint=_ENDPOINT, api_key="az-key")
    resp = await llm.complete(_req())
    assert resp.text == "ack"
    assert resp.provider == "azure"
    sent = route.calls.last.request
    # EXACT URL including the deployment path + api-version query.
    assert str(sent.url) == url
    assert sent.headers["api-key"] == "az-key"
    assert "authorization" not in {k.lower() for k in sent.headers}
    await llm.aclose()


@respx.mock
async def test_azure_custom_api_version() -> None:
    url = _deployment_url("dep", "2024-10-21")
    route = respx.post(url).mock(return_value=Response(200, json=_ok_body()))
    llm = AzureOpenAIClient(
        deployment="dep", endpoint=_ENDPOINT, api_key="k", api_version="2024-10-21"
    )
    await llm.complete(_req())
    assert "api-version=2024-10-21" in str(route.calls.last.request.url)
    await llm.aclose()


def test_azure_api_version_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")
    llm = AzureOpenAIClient(deployment="dep", endpoint=_ENDPOINT, api_key="k")
    try:
        assert llm.api_version == "2025-01-01-preview"
        assert "api-version=2025-01-01-preview" in llm._request_url()
    finally:
        import asyncio

        asyncio.run(llm.aclose())


def test_azure_endpoint_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", _ENDPOINT)
    llm = AzureOpenAIClient(deployment="dep", api_key="k")
    try:
        assert llm.endpoint == _ENDPOINT
    finally:
        import asyncio

        asyncio.run(llm.aclose())


def test_azure_missing_endpoint_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    with pytest.raises(LLMAuthError, match="ENDPOINT"):
        AzureOpenAIClient(deployment="dep", api_key="k")


def test_azure_missing_key_and_no_entra_raises() -> None:
    with pytest.raises(LLMAuthError, match="API key"):
        AzureOpenAIClient(deployment="dep", endpoint=_ENDPOINT, api_key=None)


def test_azure_endpoint_trailing_slash_normalised() -> None:
    llm = AzureOpenAIClient(deployment="dep", endpoint=_ENDPOINT + "/", api_key="k")
    try:
        assert llm.endpoint == _ENDPOINT
        assert "//openai" not in llm._request_url()
    finally:
        import asyncio

        asyncio.run(llm.aclose())


# --- Entra mode ---------------------------------------------------------


class _FakeToken:
    def __init__(self, token: str, expires_on: float) -> None:
        self.token = token
        self.expires_on = expires_on


class _FakeCredential:
    def __init__(self) -> None:
        self.calls = 0

    def get_token(self, scope: str) -> _FakeToken:
        self.calls += 1
        return _FakeToken(token="az-entra-test", expires_on=2_000_000_000.0)


@respx.mock
async def test_azure_entra_mode_uses_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_guardian.llm.azure_openai as az

    monkeypatch.setattr(az, "_AZURE_IDENTITY_AVAILABLE", True)
    fake = _FakeCredential()
    monkeypatch.setattr(az, "DefaultAzureCredential", lambda: fake, raising=False)

    url = _deployment_url("dep", "2024-10-21")
    route = respx.post(url).mock(return_value=Response(200, json=_ok_body()))
    llm = AzureOpenAIClient(deployment="dep", endpoint=_ENDPOINT, use_entra=True)
    await llm.complete(_req())
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer az-entra-test"
    assert "api-key" not in {k.lower() for k in sent.headers}
    await llm.aclose()


async def test_azure_entra_token_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_guardian.llm.azure_openai as az

    monkeypatch.setattr(az, "_AZURE_IDENTITY_AVAILABLE", True)
    fake = _FakeCredential()
    monkeypatch.setattr(az, "DefaultAzureCredential", lambda: fake, raising=False)
    llm = AzureOpenAIClient(deployment="dep", endpoint=_ENDPOINT, use_entra=True)
    try:
        # Minting happens off-thread in _prepare_request; _headers reads the
        # cached token. Two prepare calls → token minted exactly once.
        await llm._prepare_request()
        await llm._prepare_request()
        assert fake.calls == 1
        assert llm._headers()["authorization"] == "Bearer az-entra-test"
    finally:
        await llm.aclose()


def test_azure_entra_without_identity_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_guardian.llm.azure_openai as az

    monkeypatch.setattr(az, "_AZURE_IDENTITY_AVAILABLE", False)
    monkeypatch.setattr(az, "_AZURE_IDENTITY_IMPORT_ERROR", ImportError("no azure-identity"))
    with pytest.raises(LLMAuthError, match="azure-identity"):
        AzureOpenAIClient(deployment="dep", endpoint=_ENDPOINT, use_entra=True)
