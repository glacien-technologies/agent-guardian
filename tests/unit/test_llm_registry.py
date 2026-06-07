"""Tests for the provider registry + model-spec grammar.

No httpx here — pure ``parse_model_spec`` grammar tests plus ``build_llm``
construction tests that mock env vars and assert the right client class is
returned, including the missing-extra / missing-credential failure paths.
"""

from __future__ import annotations

import pytest

from agent_guardian.llm.anthropic import AnthropicClient
from agent_guardian.llm.azure_openai import AzureOpenAIClient
from agent_guardian.llm.gemini import GeminiClient
from agent_guardian.llm.ollama import OllamaClient
from agent_guardian.llm.openai import OpenAIClient
from agent_guardian.llm.openai_compat import OpenAICompatClient
from agent_guardian.llm.registry import (
    ProviderSpec,
    RegistryError,
    build_llm,
    parse_model_spec,
)
from agent_guardian.llm.stub import StubLLM
from agent_guardian.llm.vertex import VertexClient

# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "provider", "model", "qualifiers"),
    [
        ("stub", "stub", "", {}),
        ("", "stub", "", {}),
        ("openai:gpt-4o", "openai", "gpt-4o", {}),
        ("anthropic:claude-sonnet-4-6", "anthropic", "claude-sonnet-4-6", {}),
        # First-colon-only split keeps OpenRouter's slash-namespaced model intact.
        (
            "openrouter:anthropic/claude-3.5-sonnet",
            "openrouter",
            "anthropic/claude-3.5-sonnet",
            {},
        ),
        # Qualifiers — order-independent key=value pairs.
        (
            "vertex:gemini-2.5-flash+project=p+location=us-central1",
            "vertex",
            "gemini-2.5-flash",
            {"project": "p", "location": "us-central1"},
        ),
        # A qualifier value may itself contain a colon (https URL).
        (
            "azure:my-dep+endpoint=https://r.openai.azure.com",
            "azure",
            "my-dep",
            {"endpoint": "https://r.openai.azure.com"},
        ),
        ("vllm:m+base_url=http://h:8000/v1", "vllm", "m", {"base_url": "http://h:8000/v1"}),
        # Heuristic prefix inference (no colon) — unchanged.
        ("gpt-4o", "openai", "gpt-4o", {}),
        ("o3-mini", "openai", "o3-mini", {}),
        ("claude-haiku-4-5", "anthropic", "claude-haiku-4-5", {}),
        ("gemini-2.5-flash", "gemini", "gemini-2.5-flash", {}),
        ("ollama-llama3", "ollama", "ollama-llama3", {}),
        ("mystery-model", "unknown", "mystery-model", {}),
        # Fireworks model id is case-sensitive — preserved.
        (
            "fireworks:accounts/fireworks/models/DeepSeek-V3",
            "fireworks",
            "accounts/fireworks/models/DeepSeek-V3",
            {},
        ),
    ],
)
def test_parse_model_spec(spec: str, provider: str, model: str, qualifiers: dict[str, str]) -> None:
    parsed = parse_model_spec(spec)
    assert parsed == ProviderSpec(provider=provider, model=model, qualifiers=qualifiers)


def test_parse_model_spec_bare_flag_qualifier() -> None:
    parsed = parse_model_spec("azure:my-dep+v1_compat")
    assert parsed.qualifiers == {"v1_compat": "true"}


# ---------------------------------------------------------------------------
# build_llm — backward compatibility + every provider constructs
# ---------------------------------------------------------------------------


def _close(llm: object) -> None:
    import asyncio

    aclose = getattr(llm, "aclose", None)
    if aclose is not None:
        asyncio.run(aclose())


def test_build_stub_and_empty() -> None:
    assert isinstance(build_llm("stub", "attacker"), StubLLM)
    assert isinstance(build_llm("", "attacker"), StubLLM)


def test_build_ollama_no_key() -> None:
    llm = build_llm("ollama:llama3.1", "attacker")
    assert isinstance(llm, OllamaClient)
    _close(llm)


def test_build_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    llm = build_llm("openai:gpt-4o", "attacker")
    assert isinstance(llm, OpenAIClient)
    assert llm.api_key == "sk-test"
    _close(llm)


def test_build_openai_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    with pytest.raises(RegistryError, match="no API key"):
        build_llm("openai:gpt-4o", "attacker")


def test_build_anthropic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    llm = build_llm("claude-haiku-4-5", "commander")
    assert isinstance(llm, AnthropicClient)
    _close(llm)


def test_build_gemini(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    llm = build_llm("gemini:gemini-2.5-flash", "evaluator")
    assert isinstance(llm, GeminiClient)
    _close(llm)


@pytest.mark.parametrize(
    ("spec", "key_env", "base_url"),
    [
        (
            "openrouter:anthropic/claude-3.5-sonnet",
            "OPENROUTER_API_KEY",
            "https://openrouter.ai/api/v1",
        ),
        ("groq:llama-3.3-70b-versatile", "GROQ_API_KEY", "https://api.groq.com/openai/v1"),
        ("together:deepseek-ai/DeepSeek-V3", "TOGETHER_API_KEY", "https://api.together.xyz/v1"),
        (
            "fireworks:accounts/fireworks/models/deepseek-v3p1",
            "FIREWORKS_API_KEY",
            "https://api.fireworks.ai/inference/v1",
        ),
    ],
)
def test_build_gateways(
    monkeypatch: pytest.MonkeyPatch, spec: str, key_env: str, base_url: str
) -> None:
    monkeypatch.setenv(key_env, "gw-key")
    llm = build_llm(spec, "attacker")
    assert isinstance(llm, OpenAICompatClient)
    assert not isinstance(llm, OpenAIClient)
    assert llm.base_url == base_url
    assert llm.api_key == "gw-key"
    _close(llm)


def test_build_gateway_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_GROQ_API_KEY", raising=False)
    with pytest.raises(RegistryError, match="no API key"):
        build_llm("groq:llama-3.3-70b-versatile", "attacker")


def test_build_openrouter_attribution_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
    monkeypatch.setenv("OPENROUTER_HTTP_REFERER", "https://example.com")
    monkeypatch.setenv("OPENROUTER_SITE_NAME", "MyApp")
    llm = build_llm("openrouter:openai/gpt-5", "attacker")
    assert isinstance(llm, OpenAICompatClient)
    headers = llm._headers()
    assert headers["HTTP-Referer"] == "https://example.com"
    assert headers["X-Title"] == "MyApp"
    _close(llm)


def test_build_vllm_no_key_default_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VLLM_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_VLLM_API_KEY", raising=False)
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)
    llm = build_llm("vllm:NousResearch/Meta-Llama-3-8B-Instruct", "attacker")
    assert isinstance(llm, OpenAICompatClient)
    assert llm.base_url == "http://localhost:8000/v1"
    assert llm.api_key is None
    # No api_key → no Authorization header.
    assert "authorization" not in {k.lower() for k in llm._headers()}
    _close(llm)


def test_build_vllm_base_url_qualifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)
    llm = build_llm("vllm:my-model+base_url=http://gpu:9000/v1", "attacker")
    assert llm.base_url == "http://gpu:9000/v1"
    _close(llm)


def test_build_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://r.openai.azure.com")
    monkeypatch.delenv("AZURE_USE_ENTRA", raising=False)
    llm = build_llm("azure:my-gpt4o-deployment", "attacker")
    assert isinstance(llm, AzureOpenAIClient)
    assert llm.deployment == "my-gpt4o-deployment"
    assert llm.endpoint == "https://r.openai.azure.com"
    _close(llm)


def test_build_azure_missing_endpoint_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_USE_ENTRA", raising=False)
    with pytest.raises(RegistryError, match="ENDPOINT"):
        build_llm("azure:my-dep", "attacker")


def test_build_vertex_missing_project_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    with pytest.raises(RegistryError, match="project"):
        build_llm("vertex:gemini-2.5-flash", "attacker")


def test_build_vertex_with_qualifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    llm = build_llm("vertex:gemini-2.5-flash+project=p+location=global", "attacker")
    assert isinstance(llm, VertexClient)
    assert llm.project == "p"
    assert llm.location == "global"
    _close(llm)


def test_build_unknown_provider_raises() -> None:
    with pytest.raises(RegistryError, match="Cannot infer provider"):
        build_llm("nope:some-model", "attacker")


def test_build_bedrock_without_botocore(monkeypatch: pytest.MonkeyPatch) -> None:
    """When botocore is absent the registry surfaces a clear install hint."""
    import agent_guardian.llm.bedrock as bedrock_mod

    monkeypatch.setattr(bedrock_mod, "_BOTOCORE_AVAILABLE", False)
    monkeypatch.setattr(bedrock_mod, "_BOTOCORE_IMPORT_ERROR", ImportError("no botocore"))
    with pytest.raises(RegistryError, match=r"credentials are missing|AWS"):
        build_llm("bedrock:anthropic.claude-haiku-4-5-v1:0", "attacker")


def test_build_azure_entra_without_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """AZURE_USE_ENTRA=1 without azure-identity → clear install hint."""
    import agent_guardian.llm.azure_openai as az

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://r.openai.azure.com")
    monkeypatch.setenv("AZURE_USE_ENTRA", "1")
    monkeypatch.setattr(az, "_AZURE_IDENTITY_AVAILABLE", False)
    monkeypatch.setattr(az, "_AZURE_IDENTITY_IMPORT_ERROR", ImportError("no azure-identity"))
    with pytest.raises(RegistryError, match="azure-identity"):
        build_llm("azure:my-dep", "attacker")
