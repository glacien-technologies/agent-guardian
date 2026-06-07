"""Tests for the fail-fast model validation probe (QA-001).

Covers the acceptance matrix in DESIGN_LOCK §QA-001:

* stub spec → ``valid`` with no network at all.
* Unknown gemini id → ``not_found`` + Vertex cross-check suggestion text
  matches the spec'd phrasing.
* Unknown openai id → ``not_found`` + difflib suggestion text matches.
* 5xx during probe is treated as ``transient`` (proceed with warning),
  never fail-fast — a Google outage must not block scans.
* Validation result is cached per-session — two calls = one mock hit.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from agent_guardian.llm.validation import (
    EXIT_LLM_PROVIDER,
    KNOWN_MODELS,
    ModelValidationResult,
    check_model_exists,
    clear_cache,
    split_spec,
)

# Anchored regex matching the exact Vertex AI host: either the global
# ``aiplatform.googleapis.com`` or a regional ``<region>-aiplatform.googleapis.com``
# label (e.g. ``us-central1-aiplatform.googleapis.com``,
# ``europe-west4-aiplatform.googleapis.com``). The leading ``^`` and trailing
# ``$`` make a suffix-attack like ``evil-aiplatform.googleapis.com`` impossible.
# The region segment is one-or-more hyphen-separated lowercase-alnum labels,
# each ending the run with ``-`` before the literal ``aiplatform`` token.
_VERTEX_HOST_RE = re.compile(r"^(?:[a-z0-9]+-)*aiplatform\.googleapis\.com$")

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_cache_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test gets a fresh cache + a clean credential env.

    The autouse pattern keeps every test hermetic — no cross-test leakage of
    cached probe results or stray ``GEMINI_API_KEY`` values from the runner's
    environment.
    """
    clear_cache()
    for var in (
        "AGENT_GUARDIAN_OPENAI_API_KEY",
        "OPENAI_API_KEY",
        "AGENT_GUARDIAN_ANTHROPIC_API_KEY",
        "ANTHROPIC_API_KEY",
        "AGENT_GUARDIAN_GEMINI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OLLAMA_HOST",
        "AGENT_GUARDIAN_SKIP_MODEL_PROBE",
        "AGENT_GUARDIAN_MODEL_PROBE_TIMEOUT",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_API_KEY",
        "AGENT_GUARDIAN_AZURE_API_KEY",
        "AZURE_OPENAI_API_VERSION",
        "AZURE_USE_ENTRA",
        "OPENROUTER_API_KEY",
        "AGENT_GUARDIAN_OPENROUTER_API_KEY",
        "GROQ_API_KEY",
        "AGENT_GUARDIAN_GROQ_API_KEY",
        "TOGETHER_API_KEY",
        "AGENT_GUARDIAN_TOGETHER_API_KEY",
        "FIREWORKS_API_KEY",
        "AGENT_GUARDIAN_FIREWORKS_API_KEY",
        "VLLM_API_KEY",
        "AGENT_GUARDIAN_VLLM_API_KEY",
        "VLLM_BASE_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    # Set a dummy key so probes can run without bailing on auth.
    monkeypatch.setenv("AGENT_GUARDIAN_OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", "anth-test")
    monkeypatch.setenv("AGENT_GUARDIAN_GEMINI_API_KEY", "gem-test")


def _client_factory_from(handler: Callable[[httpx.Request], httpx.Response]) -> type[httpx.Client]:
    """Wrap an httpx handler in a Client subclass.

    ``check_model_exists`` accepts a ``client_factory: type[httpx.Client]``
    so tests can route every probe through a deterministic MockTransport.
    """
    transport = httpx.MockTransport(handler)

    class _MockClient(httpx.Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.pop("transport", None)
            super().__init__(*args, transport=transport, **kwargs)

    return _MockClient


# ---------------------------------------------------------------------------
# Acceptance: stub spec returns valid with no probe.
# ---------------------------------------------------------------------------


def test_stub_spec_returns_valid_without_probe() -> None:
    """``stub`` (and empty) must skip the network entirely."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - asserted not hit
        calls.append(request)
        return httpx.Response(500)

    factory = _client_factory_from(handler)
    result = check_model_exists("stub", client_factory=factory)
    assert result.valid is True
    assert result.status == "valid"
    assert result.provider == "stub"
    assert calls == []  # no network at all

    # Empty string is also "stub".
    clear_cache()
    result_empty = check_model_exists("", client_factory=factory)
    assert result_empty.valid is True
    assert result_empty.status == "valid"


# ---------------------------------------------------------------------------
# Acceptance: unknown gemini id → not_found + Vertex cross-check suggestion.
# ---------------------------------------------------------------------------


def test_unknown_gemini_with_vertex_available_suggests_vertex_prefix() -> None:
    """When AI Studio 404s but Vertex 200s, the result must suggest
    ``--model vertex:<id>`` per the QA-001 addendum spec."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "generativelanguage.googleapis.com":
            return httpx.Response(
                404,
                json={
                    "error": {
                        "code": 404,
                        "message": ("models/gemini-3.1-flash is not found for API version v1beta"),
                        "status": "NOT_FOUND",
                    }
                },
            )
        # Match Vertex AI regional endpoints — exactly `<region>-aiplatform.googleapis.com`
        # — without permitting an arbitrary-prefix substring match.
        # codeql[py/incomplete-url-substring-sanitization] -- anchored regex on httpx.Request.url.host (full-string match), not a substring check
        if _VERTEX_HOST_RE.match(host):
            return httpx.Response(200, json={"name": "publishers/google/models/gemini-3.1-flash"})
        return httpx.Response(500)  # pragma: no cover

    factory = _client_factory_from(handler)
    result = check_model_exists("gemini:gemini-3.1-flash", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"
    assert result.provider == "gemini"
    assert result.model == "gemini-3.1-flash"
    # Spec'd phrasing — Vertex hint takes precedence over difflib.
    assert "Unknown model id 'gemini-3.1-flash'" in result.message
    assert "Google AI / AI Studio" in result.message
    assert "Vertex AI" in result.message
    assert "--model vertex:gemini-3.1-flash" in result.message
    assert result.suggestion == "--model vertex:gemini-3.1-flash"


def test_unknown_gemini_no_vertex_falls_back_to_difflib() -> None:
    """When Vertex doesn't have it either, the message uses the difflib
    nearest-name from ``KNOWN_MODELS['gemini']`` instead."""

    def handler(request: httpx.Request) -> httpx.Response:
        # Both AI Studio and Vertex 404.
        return httpx.Response(404, json={"error": {"message": "not found"}})

    factory = _client_factory_from(handler)
    result = check_model_exists("gemini:gemini-3.0-flash-banana", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"
    assert "Vertex" not in result.message  # no false Vertex hint
    # difflib should produce a close match against gemini-2.5-flash /
    # gemini-1.5-flash family.
    assert result.suggestion.startswith("--model gemini:gemini-")


# ---------------------------------------------------------------------------
# Acceptance: unknown openai id → not_found + difflib suggestion.
# ---------------------------------------------------------------------------


def test_unknown_openai_id_returns_invalid_with_difflib_suggestion() -> None:
    """An openai 404 must surface a clear ``did you mean`` line that
    points at the nearest entry in ``KNOWN_MODELS['openai']``."""
    handler_calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        handler_calls.append(request)
        return httpx.Response(
            404,
            json={
                "error": {
                    "message": "The model `gpt-4o-mni` does not exist",
                    "type": "invalid_request_error",
                    "code": "model_not_found",
                }
            },
        )

    factory = _client_factory_from(handler)
    result = check_model_exists("openai:gpt-4o-mni", client_factory=factory)

    assert result.valid is False
    assert result.status == "not_found"
    assert result.provider == "openai"
    assert "Unknown model id 'gpt-4o-mni'" in result.message
    assert "OpenAI" in result.message
    assert result.suggestion == "--model openai:gpt-4o-mini"
    # The Authorization header must have been applied.
    assert handler_calls[0].headers["Authorization"].startswith("Bearer ")


# ---------------------------------------------------------------------------
# Acceptance: 5xx → transient (proceed with warning, never fail-fast).
# ---------------------------------------------------------------------------


def test_5xx_during_probe_is_treated_as_transient_not_fail_fast() -> None:
    """A Google / OpenAI outage must NOT block the scan."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="service unavailable")

    factory = _client_factory_from(handler)
    result = check_model_exists("gemini:gemini-2.5-flash", client_factory=factory)
    assert result.valid is True  # CRUCIAL — the scan continues
    assert result.status == "transient"
    assert "could not validate" in result.message
    assert "will surface at first call" in result.message


def test_network_timeout_during_probe_is_transient() -> None:
    """``httpx.TimeoutException`` must also degrade to transient, not fail-fast."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout reading from server")

    factory = _client_factory_from(handler)
    result = check_model_exists("openai:gpt-4o", client_factory=factory)
    assert result.valid is True
    assert result.status == "transient"


# ---------------------------------------------------------------------------
# Acceptance: result is cached per-session — second call = zero new probes.
# ---------------------------------------------------------------------------


def test_validation_result_is_cached_per_session() -> None:
    """Two calls with the same ``(provider, model)`` → one mock request."""
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, json={"id": "gpt-4o", "object": "model"})

    factory = _client_factory_from(handler)
    first = check_model_exists("openai:gpt-4o", client_factory=factory)
    second = check_model_exists("openai:gpt-4o", client_factory=factory)

    assert first.valid is True and second.valid is True
    assert first.status == "valid" and second.status == "valid"
    assert request_count == 1  # cache hit on the second call


def test_clear_cache_forces_reprobe() -> None:
    """The testing helper must actually clear the cache."""
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, json={"id": "gpt-4o", "object": "model"})

    factory = _client_factory_from(handler)
    check_model_exists("openai:gpt-4o", client_factory=factory)
    clear_cache()
    check_model_exists("openai:gpt-4o", client_factory=factory)
    assert request_count == 2


# ---------------------------------------------------------------------------
# Provider-specific coverage (each probe path).
# ---------------------------------------------------------------------------


def test_known_gemini_id_returns_valid() -> None:
    """``gemini:gemini-2.5-flash`` → valid (the regression sentinel)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "name": "models/gemini-2.5-flash",
                "supportedGenerationMethods": ["generateContent"],
            },
        )

    factory = _client_factory_from(handler)
    result = check_model_exists("gemini:gemini-2.5-flash", client_factory=factory)
    assert result.valid is True
    assert result.status == "valid"


def test_gemini_uses_query_param_key_not_header() -> None:
    """AI Studio auth is via ``?key=…`` query param — never an Authorization header."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"name": "models/gemini-2.5-flash"})

    factory = _client_factory_from(handler)
    check_model_exists("gemini:gemini-2.5-flash", client_factory=factory)
    assert seen
    req = seen[0]
    assert req.url.params.get("key") == "gem-test"
    assert "Authorization" not in req.headers


def test_vertex_probe_anonymous_no_auth_header_sent() -> None:
    """The Vertex publisher catalog probe must NOT include credentials."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"name": "publishers/google/models/gemini-2.5-flash"})

    factory = _client_factory_from(handler)
    result = check_model_exists("vertex:gemini-2.5-flash", client_factory=factory)
    assert result.valid is True
    assert seen
    assert "Authorization" not in seen[0].headers
    # x-api-key would betray a key bleed from another provider's env var.
    assert "x-api-key" not in seen[0].headers


def test_anthropic_known_id_returns_valid() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-api-key") == "anth-test"
        assert request.headers.get("anthropic-version") == "2023-06-01"
        return httpx.Response(200, json={"id": "claude-opus-4-5", "type": "model"})

    factory = _client_factory_from(handler)
    result = check_model_exists("anthropic:claude-opus-4-5", client_factory=factory)
    assert result.valid is True
    assert result.status == "valid"


def test_anthropic_unknown_id_returns_not_found_with_suggestion() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={
                "type": "error",
                "error": {"type": "not_found_error", "message": "model not found"},
            },
        )

    factory = _client_factory_from(handler)
    result = check_model_exists("anthropic:claude-opus-4-9", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"
    assert "Anthropic" in result.message
    assert result.suggestion.startswith("--model anthropic:claude-")


# ---------------------------------------------------------------------------
# Auth handling.
# ---------------------------------------------------------------------------


def test_missing_openai_key_returns_auth_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = check_model_exists("openai:gpt-4o")
    assert result.valid is False
    assert result.status == "auth_failed"
    assert "AGENT_GUARDIAN_OPENAI_API_KEY" in result.message


def test_401_from_openai_returns_auth_failed_with_envvar_hint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid api key"}})

    factory = _client_factory_from(handler)
    result = check_model_exists("openai:gpt-4o", client_factory=factory)
    assert result.valid is False
    assert result.status == "auth_failed"
    assert "AGENT_GUARDIAN_OPENAI_API_KEY" in result.message


def test_missing_gemini_key_returns_auth_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    result = check_model_exists("gemini:gemini-2.5-flash")
    assert result.valid is False
    assert result.status == "auth_failed"
    assert "GEMINI_API_KEY" in result.message or "GOOGLE_API_KEY" in result.message


# ---------------------------------------------------------------------------
# Ollama.
# ---------------------------------------------------------------------------


def test_ollama_found_via_api_show() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Ollama's /api/show is a POST.
        assert request.method == "POST"
        assert request.url.path == "/api/show"
        return httpx.Response(200, json={"modelfile": "...", "parameters": "..."})

    factory = _client_factory_from(handler)
    result = check_model_exists("ollama:llama3", client_factory=factory)
    assert result.valid is True
    assert result.status == "valid"


def test_ollama_daemon_unreachable_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    factory = _client_factory_from(handler)
    result = check_model_exists("ollama:llama3", client_factory=factory)
    assert result.valid is True
    assert result.status == "transient"
    assert "OLLAMA_HOST" in result.message


# ---------------------------------------------------------------------------
# split_spec heuristic.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("stub", ("stub", "")),
        ("", ("stub", "")),
        ("gpt-4o", ("openai", "gpt-4o")),
        ("claude-opus-4-5", ("anthropic", "claude-opus-4-5")),
        ("gemini-2.5-flash", ("gemini", "gemini-2.5-flash")),
        ("ollama-llama3", ("ollama", "ollama-llama3")),
        ("openai:gpt-4o", ("openai", "gpt-4o")),
        ("gemini:gemini-3.1-flash", ("gemini", "gemini-3.1-flash")),
        ("vertex:gemini-1.5-pro", ("vertex", "gemini-1.5-pro")),
        ("bedrock:anthropic.claude-haiku-4-5", ("bedrock", "anthropic.claude-haiku-4-5")),
    ],
)
def test_split_spec_matches_cli_factory_rules(spec: str, expected: tuple[str, str]) -> None:
    assert split_spec(spec) == expected


def test_unknown_provider_passes_through_as_unsupported() -> None:
    """Specs we can't route (e.g. bare ``"frobnitz"``) must not fail-fast —
    let the LLM factory raise its own BadParameter at construction time."""
    result = check_model_exists("frobnitz")
    assert result.valid is True
    assert result.status == "unsupported"


# ---------------------------------------------------------------------------
# Env switches.
# ---------------------------------------------------------------------------


def test_skip_env_var_bypasses_probe_entirely(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_SKIP_MODEL_PROBE", "1")
    # No client_factory; if the probe ran, it would hit the real internet.
    # Hardcoded valid result instead.
    result = check_model_exists("gemini:gemini-doesnt-exist")
    assert result.valid is True
    assert result.status == "valid"


def test_probe_timeout_override_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_MODEL_PROBE_TIMEOUT", "1.5")
    captured: dict[str, float] = {}

    class _CapturingClient(httpx.Client):
        def __init__(self, *args: Any, timeout: Any = None, **kwargs: Any) -> None:
            captured["timeout"] = float(timeout) if timeout is not None else 0.0
            kwargs.pop("transport", None)
            super().__init__(
                *args,
                timeout=timeout,
                transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"id": "ok"})),
                **kwargs,
            )

    check_model_exists("openai:gpt-4o", client_factory=_CapturingClient)
    assert captured["timeout"] == 1.5


def test_invalid_timeout_env_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_MODEL_PROBE_TIMEOUT", "not-a-number")
    captured: dict[str, float] = {}

    class _CapturingClient(httpx.Client):
        def __init__(self, *args: Any, timeout: Any = None, **kwargs: Any) -> None:
            captured["timeout"] = float(timeout) if timeout is not None else 0.0
            kwargs.pop("transport", None)
            super().__init__(
                *args,
                timeout=timeout,
                transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"id": "ok"})),
                **kwargs,
            )

    check_model_exists("openai:gpt-4o", client_factory=_CapturingClient)
    assert captured["timeout"] == 4.0  # default


# ---------------------------------------------------------------------------
# Result surface.
# ---------------------------------------------------------------------------


def test_known_models_contains_stable_families() -> None:
    """Sanity-check the ``did you mean`` allow-list shape."""
    assert "gpt-4o" in KNOWN_MODELS["openai"]
    assert "gemini-2.5-flash" in KNOWN_MODELS["gemini"]
    assert "claude-opus-4-5" in KNOWN_MODELS["anthropic"]


def test_exit_code_is_4_for_unknown_model() -> None:
    """Sentinel — the CLI integration expects EXIT_LLM_PROVIDER == 4."""
    assert EXIT_LLM_PROVIDER == 4


def test_model_validation_result_is_frozen() -> None:
    """``frozen=True`` is part of the contract — callers may rely on it."""
    from dataclasses import FrozenInstanceError

    result = ModelValidationResult(valid=True, status="valid")
    with pytest.raises(FrozenInstanceError):
        result.valid = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Dedup across roles (attacker == evaluator == commander).
# ---------------------------------------------------------------------------


def test_three_role_dedup_only_one_probe() -> None:
    """Calling ``check_model_exists`` three times with the same spec
    (attacker / evaluator / commander) must cost exactly one HTTP probe."""
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, json={"id": "gpt-4o"})

    factory = _client_factory_from(handler)
    for _ in range(3):
        check_model_exists("openai:gpt-4o", client_factory=factory)
    assert request_count == 1


# ---------------------------------------------------------------------------
# Bedrock degrades to unsupported when boto3 is absent (so we don't hard-fail
# in dev environments that haven't installed the [aws] extra).
# ---------------------------------------------------------------------------


def test_bedrock_without_boto3_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the ImportError branch by intercepting the import. boto3 may
    # actually be installed in the test env; we simulate the absence.
    import builtins

    real_import = builtins.__import__

    def _import_blocker(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "boto3":
            raise ImportError("boto3 not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import_blocker)
    result = check_model_exists("bedrock:anthropic.claude-haiku-4-5")
    assert result.valid is True
    assert result.status == "unsupported"
    assert "boto3" in result.message


def _install_fake_boto3(monkeypatch: pytest.MonkeyPatch, *, behaviour: str) -> None:
    """Inject a fake ``boto3`` + ``botocore.exceptions`` so the bedrock probe
    can be exercised without the optional ``[aws]`` extra installed."""
    import sys
    import types

    boto3 = types.ModuleType("boto3")
    botocore = types.ModuleType("botocore")
    botocore_exc = types.ModuleType("botocore.exceptions")

    class _ClientError(Exception):
        def __init__(self, response: dict[str, Any], operation_name: str = "op") -> None:
            super().__init__(response.get("Error", {}).get("Message", "client error"))
            self.response = response

    class _NoCredentialsError(Exception):
        def __init__(self) -> None:
            super().__init__("no credentials")

    botocore_exc.ClientError = _ClientError  # type: ignore[attr-defined]
    botocore_exc.NoCredentialsError = _NoCredentialsError  # type: ignore[attr-defined]

    class _BedrockClient:
        def get_foundation_model(self, *, modelIdentifier: str) -> dict[str, Any]:
            if behaviour == "found":
                return {"modelDetails": {"modelId": modelIdentifier}}
            if behaviour == "not_found":
                raise _ClientError(
                    {"Error": {"Code": "ResourceNotFoundException", "Message": "no"}},
                    "GetFoundationModel",
                )
            if behaviour == "auth":
                raise _NoCredentialsError()
            if behaviour == "transient":
                raise _ClientError(
                    {"Error": {"Code": "ThrottlingException", "Message": "slow down"}},
                    "GetFoundationModel",
                )
            raise AssertionError(f"unknown behaviour {behaviour}")

    def _client(service: str, region_name: str | None = None) -> _BedrockClient:
        assert service == "bedrock"
        return _BedrockClient()

    boto3.client = _client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", botocore_exc)


def test_bedrock_found_via_stubbed_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_boto3(monkeypatch, behaviour="found")
    result = check_model_exists("bedrock:anthropic.claude-haiku-4-5")
    assert result.valid is True
    assert result.status == "valid"
    assert result.provider == "bedrock"


def test_bedrock_not_found_via_stubbed_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_boto3(monkeypatch, behaviour="not_found")
    result = check_model_exists("bedrock:anthropic.claude-doesnt-exist")
    assert result.valid is False
    assert result.status == "not_found"
    assert "Unknown Bedrock model id" in result.message


def test_bedrock_no_credentials_is_auth_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_boto3(monkeypatch, behaviour="auth")
    result = check_model_exists("bedrock:anthropic.claude-haiku-4-5")
    assert result.valid is False
    assert result.status == "auth_failed"
    assert "credentials missing" in result.message


def test_bedrock_other_client_error_is_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_boto3(monkeypatch, behaviour="transient")
    result = check_model_exists("bedrock:anthropic.claude-haiku-4-5")
    assert result.valid is True
    assert result.status == "transient"


def test_bedrock_with_aws_region_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure the ``AWS_REGION`` branch is exercised (passes ``region_name``)."""
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    _install_fake_boto3(monkeypatch, behaviour="found")
    result = check_model_exists("bedrock:anthropic.claude-haiku-4-5")
    assert result.valid is True


def test_openai_known_id_returns_valid() -> None:
    """Direct happy-path coverage for the openai probe's 200 branch."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "gpt-4o", "object": "model"})

    factory = _client_factory_from(handler)
    result = check_model_exists("openai:gpt-4o", client_factory=factory)
    assert result.valid is True
    assert result.status == "valid"


def test_anthropic_missing_key_returns_auth_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = check_model_exists("anthropic:claude-opus-4-5")
    assert result.valid is False
    assert result.status == "auth_failed"
    assert "ANTHROPIC_API_KEY" in result.message


def test_anthropic_401_returns_auth_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid"}})

    factory = _client_factory_from(handler)
    result = check_model_exists("anthropic:claude-opus-4-5", client_factory=factory)
    assert result.valid is False
    assert result.status == "auth_failed"


def test_vertex_404_returns_not_found_with_hint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"message": "not found"}})

    factory = _client_factory_from(handler)
    result = check_model_exists("vertex:gemini-doesnt-exist", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"
    assert "Vertex AI" in result.message


def test_ollama_unknown_model_returns_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'foo' not found, try pulling it first"})

    factory = _client_factory_from(handler)
    result = check_model_exists("ollama:foo", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"


def test_gemini_400_api_key_invalid_is_auth_failed() -> None:
    """AI Studio surfaces a bad key as HTTP 400 with body containing
    ``API_KEY_INVALID``. Classify as auth-failed (actionable), not transient."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": {
                    "code": 400,
                    "message": "API key not valid. Please pass a valid API key.",
                    "status": "INVALID_ARGUMENT",
                    "details": [{"reason": "API_KEY_INVALID"}],
                }
            },
        )

    factory = _client_factory_from(handler)
    result = check_model_exists("gemini:gemini-2.5-flash", client_factory=factory)
    assert result.valid is False
    assert result.status == "auth_failed"


def test_400_non_auth_is_treated_as_not_found() -> None:
    """A 400 without API_KEY_INVALID (e.g. malformed model id) should
    surface as not-found so the user sees a 'did you mean' hint rather
    than a transient warning that will repeat at scan time."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"message": "model id malformed"}})

    factory = _client_factory_from(handler)
    result = check_model_exists("openai:gpt-banana", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"


def test_gemini_no_difflib_match_uses_stable_hint() -> None:
    """When difflib returns no match, the message falls back to the
    'Stable Gemini ids include …' phrasing instead of leaving the user
    with a bare error."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"message": "not found"}})

    factory = _client_factory_from(handler)
    result = check_model_exists("gemini:totallybogus-banana-9000", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"
    # No Vertex hint (Vertex also 404'd) and no close difflib match.
    assert (
        "Stable Gemini ids include:" in result.message
        or "Available similarly-named:" in result.message
    )


# ---------------------------------------------------------------------------
# Multi-provider probes — Azure, OpenAI-compatible gateways, vLLM.
# ---------------------------------------------------------------------------


def test_azure_missing_endpoint_is_auth_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
    result = check_model_exists("azure:my-deployment")
    assert result.valid is False
    assert result.status == "auth_failed"
    assert "endpoint" in result.message.lower()


def test_azure_deployment_exists_probes_dated_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://r.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")

    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["api-key"] = request.headers.get("api-key", "")
        return httpx.Response(200, json={"id": "my-deployment"})

    factory = _client_factory_from(handler)
    result = check_model_exists("azure:my-deployment", client_factory=factory)
    assert result.valid is True
    assert result.status == "valid"
    # Reviewer correction #2 — standard deployment path + api-version query.
    assert "/openai/deployments/my-deployment" in seen["url"]
    assert "api-version=" in seen["url"]
    assert seen["api-key"] == "az-key"


def test_azure_deployment_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://r.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "DeploymentNotFound"})

    factory = _client_factory_from(handler)
    result = check_model_exists("azure:typo-deployment", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"


def test_groq_model_in_catalog_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "gq-key")

    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"data": [{"id": "llama-3.3-70b-versatile"}]})

    factory = _client_factory_from(handler)
    result = check_model_exists("groq:llama-3.3-70b-versatile", client_factory=factory)
    assert result.valid is True
    assert result.status == "valid"
    assert seen["url"] == "https://api.groq.com/openai/v1/models"
    assert seen["auth"] == "Bearer gq-key"


def test_openrouter_model_not_in_catalog_is_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": "openai/gpt-5"}]})

    factory = _client_factory_from(handler)
    result = check_model_exists("openrouter:does/not-exist", client_factory=factory)
    assert result.valid is False
    assert result.status == "not_found"


def test_gateway_missing_key_is_auth_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOGETHER_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_GUARDIAN_TOGETHER_API_KEY", raising=False)
    result = check_model_exists("together:deepseek-ai/DeepSeek-V3")
    assert result.valid is False
    assert result.status == "auth_failed"


def test_vllm_server_unreachable_is_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VLLM_BASE_URL", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    factory = _client_factory_from(handler)
    result = check_model_exists(
        "vllm:NousResearch/Meta-Llama-3-8B-Instruct", client_factory=factory
    )
    # Self-hosted server down must NOT fail-fast the scan.
    assert result.valid is True
    assert result.status == "transient"


def test_split_spec_strips_qualifiers() -> None:
    assert split_spec("vertex:gemini-2.5-flash+project=p+location=us") == (
        "vertex",
        "gemini-2.5-flash",
    )
    assert split_spec("openrouter:anthropic/claude-3.5-sonnet") == (
        "openrouter",
        "anthropic/claude-3.5-sonnet",
    )
    assert split_spec("stub") == ("stub", "")
