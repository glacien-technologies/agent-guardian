"""Tests for the production Bedrock client (SigV4 + Converse).

The pure ``build_bedrock_payload`` / ``map_bedrock_response`` helpers are
exercised standalone; the live client surface uses ``respx`` to intercept
the signed POST so we can assert on the SigV4 headers and error mapping
without touching AWS.

Every test sets fake AWS credentials via ``monkeypatch.setenv`` because
``BedrockClient.__init__`` resolves credentials eagerly — the contract
is "fail fast at construction" so misconfigured operators don't burn
the cost-estimate countdown only to crash on the first request.
"""

from __future__ import annotations

import logging
import re

import pytest

# The Bedrock client needs the optional ``[aws]`` extra (botocore) for SigV4
# signing + the AWS credential chain. CI installs it (``uv sync --extra aws``);
# a plain ``--extra dev`` dev env does not. Skip the whole module cleanly there
# instead of erroring at import (``BedrockClient.__init__`` raises LLMAuthError
# when botocore is missing, which would otherwise red-fail every test here).
pytest.importorskip("botocore", reason="Bedrock tests require the [aws] extra (botocore)")

import httpx
import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.bedrock import (
    BEDROCK_HOST_TEMPLATE,
    BedrockClient,
    build_bedrock_payload,
    map_bedrock_response,
)
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)

# ---------------------------------------------------------------------------
# Pure-function tests — unchanged from M3.
# ---------------------------------------------------------------------------


def test_build_bedrock_payload_simple() -> None:
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="anthropic.claude-3-5-sonnet-20240620-v1:0",
    )
    payload = build_bedrock_payload(req)
    assert payload["messages"] == [{"role": "user", "content": [{"text": "hello"}]}]
    assert payload["inferenceConfig"]["maxTokens"] == 1024
    assert payload["inferenceConfig"]["temperature"] == 0.7
    assert "system" not in payload


def test_build_bedrock_payload_separates_system() -> None:
    req = LLMRequest(
        messages=[
            LLMMessage(role="system", content="be polite"),
            LLMMessage(role="system", content="also be brief"),
            LLMMessage(role="user", content="hi"),
        ],
        model="m",
    )
    payload = build_bedrock_payload(req)
    assert payload["system"] == [{"text": "be polite"}, {"text": "also be brief"}]
    assert payload["messages"] == [{"role": "user", "content": [{"text": "hi"}]}]


def test_build_bedrock_payload_stop_sequences() -> None:
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="m",
        stop=["END"],
    )
    payload = build_bedrock_payload(req)
    assert payload["inferenceConfig"]["stopSequences"] == ["END"]


def test_map_bedrock_response_happy_path() -> None:
    data = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "hi there"}],
            }
        },
        "usage": {"inputTokens": 5, "outputTokens": 3, "totalTokens": 8},
        "stopReason": "end_turn",
    }
    resp = map_bedrock_response("m", data)
    assert resp.text == "hi there"
    assert resp.provider == "bedrock"
    assert resp.usage.prompt_tokens == 5
    assert resp.usage.completion_tokens == 3
    assert resp.usage.total_tokens == 8
    assert resp.finish_reason == "stop"


def test_map_bedrock_response_concatenates_text_blocks() -> None:
    data = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "hello "}, {"text": "world"}],
            }
        },
        "usage": {"inputTokens": 0, "outputTokens": 0},
        "stopReason": "end_turn",
    }
    resp = map_bedrock_response("m", data)
    assert resp.text == "hello world"


def test_map_bedrock_response_finish_reason_mapping() -> None:
    base = {
        "output": {"message": {"role": "assistant", "content": [{"text": ""}]}},
        "usage": {"inputTokens": 0, "outputTokens": 0},
    }
    cases = {
        "end_turn": "stop",
        "max_tokens": "length",
        "tool_use": "tool_call",
        "guardrail_intervened": "content_filter",
        "weird": "stop",
    }
    for raw, expected in cases.items():
        data = {**base, "stopReason": raw}
        resp = map_bedrock_response("m", data)
        assert resp.finish_reason == expected, raw


def test_map_bedrock_response_missing_total_tokens_computed() -> None:
    data = {
        "output": {"message": {"role": "assistant", "content": [{"text": "x"}]}},
        "usage": {"inputTokens": 2, "outputTokens": 3},
        "stopReason": "end_turn",
    }
    resp = map_bedrock_response("m", data)
    assert resp.usage.total_tokens == 5


def test_map_bedrock_response_malformed_raises() -> None:
    with pytest.raises(LLMResponseFormatError):
        map_bedrock_response("m", {"unexpected": "shape"})


# ---------------------------------------------------------------------------
# Live client tests — SigV4 + Converse, mocked via respx.
# ---------------------------------------------------------------------------


# Fake but well-formed AWS credentials. ``AKIA...`` is the conventional
# 20-char access-key shape; the secret is 40 chars. botocore validates
# shape, not authenticity.
_FAKE_AKID = "AKIATESTTESTTESTTEST"
_FAKE_SECRET = "test/secret/key/for/unit/tests/0123456789"  # 40 chars


@pytest.fixture
def _fake_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plant fake AWS credentials in the environment for the duration of a test."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _FAKE_AKID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _FAKE_SECRET)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    # Make sure botocore doesn't read the user's ~/.aws/credentials and
    # discover a real SSO profile — point AWS_SHARED_CREDENTIALS_FILE at
    # a path that doesn't exist (botocore tolerates the absence cleanly).
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/aws-creds")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/aws-config")


def _converse_url(region: str = "us-east-1", model: str = "anthropic.claude-haiku-4-5-v1:0") -> str:
    return f"https://{BEDROCK_HOST_TEMPLATE.format(region=region)}/model/{model}/converse"


def _converse_url_re(region: str = "us-east-1") -> re.Pattern[str]:
    # Bedrock model IDs have dots, colons and slashes — escape the host but
    # accept any model path so individual tests can pick whichever ID they want.
    host = re.escape(BEDROCK_HOST_TEMPLATE.format(region=region))
    return re.compile(rf"https://{host}/model/.+/converse")


def _happy_response() -> Response:
    return Response(
        200,
        json={
            "output": {"message": {"role": "assistant", "content": [{"text": "ack"}]}},
            "usage": {"inputTokens": 3, "outputTokens": 1, "totalTokens": 4},
            "stopReason": "end_turn",
        },
    )


@respx.mock
async def test_bedrock_complete_happy_path(_fake_aws_env: None) -> None:
    route = respx.post(_converse_url_re()).mock(return_value=_happy_response())
    client = BedrockClient(region="us-east-1")
    try:
        resp = await client.complete(
            LLMRequest(
                messages=[LLMMessage(role="user", content="hi")],
                model="anthropic.claude-haiku-4-5-v1:0",
            )
        )
        assert resp.text == "ack"
        assert resp.provider == "bedrock"
        assert resp.model == "anthropic.claude-haiku-4-5-v1:0"
        assert resp.usage.total_tokens == 4
        assert route.called
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_complete_signs_request(_fake_aws_env: None) -> None:
    """SigV4 headers must be present on the outbound request."""
    route = respx.post(_converse_url_re()).mock(return_value=_happy_response())
    client = BedrockClient(region="us-east-1")
    try:
        await client.complete(
            LLMRequest(
                messages=[LLMMessage(role="user", content="hi")],
                model="anthropic.claude-haiku-4-5-v1:0",
            )
        )
        sent = route.calls.last.request
        # SigV4 always sets these.
        assert "X-Amz-Date" in sent.headers
        auth = sent.headers["Authorization"]
        assert auth.startswith("AWS4-HMAC-SHA256")
        assert "Credential=" in auth
        assert "/us-east-1/bedrock/aws4_request" in auth
        assert "SignedHeaders=" in auth
        assert "Signature=" in auth
        assert _FAKE_AKID in auth
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_access_denied_maps_to_auth_error(_fake_aws_env: None) -> None:
    respx.post(_converse_url_re()).mock(
        return_value=Response(
            403,
            json={
                "__type": "com.amazon.coral.service#AccessDeniedException",
                "message": "You don't have access to the model.",
            },
        )
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMAuthError) as exc_info:
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
        # The operator hint must mention the Bedrock console URL so users
        # know exactly where to click.
        assert "Model access" in str(exc_info.value)
        assert "console.aws.amazon.com/bedrock" in str(exc_info.value)
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_throttling_maps_to_rate_limit(_fake_aws_env: None) -> None:
    respx.post(_converse_url_re()).mock(
        return_value=Response(
            429,
            headers={"retry-after": "0"},
            json={
                "__type": "ThrottlingException",
                "message": "Rate exceeded",
            },
        )
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMRateLimitError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_validation_exception_maps_to_permanent(_fake_aws_env: None) -> None:
    respx.post(_converse_url_re()).mock(
        return_value=Response(
            400,
            json={
                "__type": "ValidationException",
                "message": "Invalid model parameters",
            },
        )
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMPermanentError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_model_timeout_maps_to_timeout(
    _fake_aws_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ModelTimeoutException maps to LLMTimeoutError which the retry loop
    # treats as transient — patch compute_delay so the test doesn't pay
    # the ~60s exponential-backoff total.
    from agent_guardian.llm import retry as retry_mod

    monkeypatch.setattr(retry_mod, "compute_delay", lambda *_args, **_kwargs: 0.0)
    respx.post(_converse_url_re()).mock(
        return_value=Response(
            408,
            json={
                "__type": "ModelTimeoutException",
                "message": "Model took too long",
            },
        )
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMTimeoutError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_service_unavailable_is_transient(
    _fake_aws_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two retries then succeed — proves the retry loop reaches the success path.
    # ``compute_delay`` is patched to zero so the test doesn't pay the real
    # exponential-backoff cost (~60s across 6 attempts).
    from agent_guardian.llm import retry as retry_mod

    monkeypatch.setattr(retry_mod, "compute_delay", lambda *_args, **_kwargs: 0.0)
    respx.post(_converse_url_re()).mock(
        side_effect=[
            Response(
                503,
                json={
                    "__type": "ServiceUnavailableException",
                    "message": "try later",
                },
            ),
            _happy_response(),
        ]
    )
    client = BedrockClient(region="us-east-1")
    try:
        resp = await client.complete(
            LLMRequest(
                messages=[LLMMessage(role="user", content="hi")],
                model="anthropic.claude-haiku-4-5-v1:0",
            )
        )
        assert resp.text == "ack"
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_transient_then_raises_after_retries(
    _fake_aws_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_guardian.llm import retry as retry_mod

    monkeypatch.setattr(retry_mod, "compute_delay", lambda *_args, **_kwargs: 0.0)
    respx.post(_converse_url_re()).mock(
        return_value=Response(
            500,
            json={"__type": "InternalServerException", "message": "boom"},
        )
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMTransientError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


def test_bedrock_missing_credentials_raises_at_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """No env creds + empty profile chain -> LLMAuthError at __init__."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    # Disable IMDS so we don't accidentally hit a real EC2 metadata service.
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/aws-creds")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/aws-config")

    with pytest.raises(LLMAuthError) as exc_info:
        BedrockClient(region="us-east-1")
    # The hint must name at least one of the standard fix paths.
    msg = str(exc_info.value)
    assert "AWS_ACCESS_KEY_ID" in msg or "credential" in msg.lower()


def test_bedrock_region_resolves_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _FAKE_AKID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _FAKE_SECRET)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/aws-creds")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/aws-config")

    client = BedrockClient()
    try:
        assert client.region == "eu-west-2"
        assert "eu-west-2" in client.base_url
        assert client.host() == "bedrock-runtime.eu-west-2.amazonaws.com"
    finally:
        # No async call ran; calling aclose synchronously closes the httpx client.
        import asyncio

        asyncio.run(client.aclose())


def test_bedrock_host_template(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _FAKE_AKID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _FAKE_SECRET)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/aws-creds")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/aws-config")
    client = BedrockClient(region="ap-southeast-2")
    try:
        assert client.host() == "bedrock-runtime.ap-southeast-2.amazonaws.com"
    finally:
        import asyncio

        asyncio.run(client.aclose())


@respx.mock
async def test_bedrock_explicit_region_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _FAKE_AKID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _FAKE_SECRET)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/aws-creds")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/aws-config")
    route = respx.post(_converse_url_re("ap-south-1")).mock(return_value=_happy_response())
    client = BedrockClient(region="ap-south-1")
    try:
        await client.complete(
            LLMRequest(
                messages=[LLMMessage(role="user", content="hi")],
                model="anthropic.claude-haiku-4-5-v1:0",
            )
        )
        sent = route.calls.last.request
        # The signing region must match the constructor-supplied region.
        assert "/ap-south-1/bedrock/" in sent.headers["Authorization"]
    finally:
        await client.aclose()


def test_bedrock_profile_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unknown profile must surface as LLMAuthError, not a botocore error."""
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/aws-creds")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/aws-config")
    with pytest.raises(LLMAuthError):
        BedrockClient(region="us-east-1", profile="this-profile-does-not-exist")


@respx.mock
async def test_bedrock_resource_not_found_maps_to_permanent(_fake_aws_env: None) -> None:
    """Wrong model ID (or model unavailable in region) -> LLMPermanentError."""
    respx.post(_converse_url_re()).mock(
        return_value=Response(
            404,
            json={
                "__type": "ResourceNotFoundException",
                "message": "Could not find model",
            },
        )
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMPermanentError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_expired_token_maps_to_auth(_fake_aws_env: None) -> None:
    """Expired session token (common with SSO) -> LLMAuthError."""
    respx.post(_converse_url_re()).mock(
        return_value=Response(
            403,
            json={
                "__type": "ExpiredTokenException",
                "message": "The security token has expired",
            },
        )
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMAuthError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_non_json_error_body(_fake_aws_env: None) -> None:
    """Server returns 503 with non-JSON body -> falls back to HTTP-status mapping."""
    from agent_guardian.llm import retry as retry_mod

    # 503 maps to LLMTransientError which retries; squash sleep.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(retry_mod, "compute_delay", lambda *_a, **_k: 0.0)
        respx.post(_converse_url_re()).mock(
            return_value=Response(503, content=b"<html>Gateway Error</html>")
        )
        client = BedrockClient(region="us-east-1")
        try:
            with pytest.raises(LLMTransientError):
                await client.complete(
                    LLMRequest(
                        messages=[LLMMessage(role="user", content="hi")],
                        model="anthropic.claude-haiku-4-5-v1:0",
                    )
                )
        finally:
            await client.aclose()


@respx.mock
async def test_bedrock_unknown_4xx_maps_to_permanent(_fake_aws_env: None) -> None:
    """4xx with no recognised body code -> LLMPermanentError."""
    respx.post(_converse_url_re()).mock(
        return_value=Response(418, json={"message": "I'm a teapot"})
    )
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMPermanentError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_malformed_success_body_raises(_fake_aws_env: None) -> None:
    """200 with garbage body -> LLMResponseFormatError."""
    respx.post(_converse_url_re()).mock(return_value=Response(200, content=b"not json"))
    client = BedrockClient(region="us-east-1")
    try:
        with pytest.raises(LLMResponseFormatError):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_response_model_strips_provider_prefix(_fake_aws_env: None) -> None:
    """Caller-supplied ``bedrock:<id>`` spec must NOT leak into the response.

    Cost lookup, receipts, and downstream telemetry all key off
    :attr:`LLMResponse.model`, which is the bare Bedrock model id — passing
    the spec form (with the ``bedrock:`` provider tag) through would break
    the cost table lookup silently.
    """
    respx.post(_converse_url_re()).mock(return_value=_happy_response())
    client = BedrockClient(region="us-east-1")
    try:
        resp = await client.complete(
            LLMRequest(
                messages=[LLMMessage(role="user", content="hi")],
                model="bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0",
            )
        )
        assert resp.model == "anthropic.claude-3-5-sonnet-20240620-v1:0"
        assert not resp.model.startswith("bedrock:")
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_seed_ignored_logs_once_per_process(
    _fake_aws_env: None, caplog: pytest.LogCaptureFixture
) -> None:
    """Bedrock does not support deterministic seed — we warn once, then stay quiet.

    The per-process dedupe matters because swarm runs can issue thousands
    of completions; if we logged every time the noise would drown real
    issues. We reset the class-level flag here so test ordering can't
    starve the assertion.
    """
    # Reset the module-level dedupe flag so the test is order-independent.
    from agent_guardian.llm.bedrock import BedrockClient as _BC

    _BC._seed_warning_emitted = False
    respx.post(_converse_url_re()).mock(return_value=_happy_response())
    client = BedrockClient(region="us-east-1")
    try:
        with caplog.at_level(logging.DEBUG, logger="agent_guardian.llm.bedrock"):
            for _ in range(3):
                await client.complete(
                    LLMRequest(
                        messages=[LLMMessage(role="user", content="hi")],
                        model="anthropic.claude-haiku-4-5-v1:0",
                        seed=1337,
                    )
                )
        seed_warnings = [r for r in caplog.records if "does not support seed" in r.getMessage()]
        assert len(seed_warnings) == 1, (
            f"expected exactly one seed-ignored debug warning, got {len(seed_warnings)}"
        )
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_failed_call_logs_via_helper_error_path(
    _fake_aws_env: None, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A transport failure surfaces via the shared ``log_model_response`` error
    path — one WARNING ``model call failed:`` line carrying the cause — rather
    than an ad-hoc per-provider ``bedrock network error`` line."""
    # httpx.HTTPError maps to LLMTransientError which the retry loop treats as
    # transient — patch compute_delay so the test doesn't pay the backoff.
    from agent_guardian.llm import retry as retry_mod

    monkeypatch.setattr(retry_mod, "compute_delay", lambda *_args, **_kwargs: 0.0)
    respx.post(_converse_url_re()).mock(side_effect=httpx.ConnectError("connection refused"))
    client = BedrockClient(region="us-east-1")
    try:
        with (
            caplog.at_level(logging.WARNING, logger="agent_guardian.llm.bedrock"),
            pytest.raises(LLMTransientError),
        ):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
        failed = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING and r.getMessage().startswith("model call failed:")
        ]
        assert failed, [r.getMessage() for r in caplog.records]
        assert "ConnectError" in failed[0].getMessage()
        # The old ad-hoc per-provider line is gone.
        assert not [r for r in caplog.records if "bedrock network error" in r.getMessage()]
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_invalid_json_logs_via_helper_error_path(
    _fake_aws_env: None, caplog: pytest.LogCaptureFixture
) -> None:
    """An invalid-JSON 2xx body also routes through the helper's error path."""
    respx.post(_converse_url_re()).mock(return_value=Response(200, content=b"not json"))
    client = BedrockClient(region="us-east-1")
    try:
        with (
            caplog.at_level(logging.WARNING, logger="agent_guardian.llm.bedrock"),
            pytest.raises(LLMResponseFormatError),
        ):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
        failed = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING and r.getMessage().startswith("model call failed:")
        ]
        assert failed, [r.getMessage() for r in caplog.records]
    finally:
        await client.aclose()


@respx.mock
async def test_bedrock_seed_omitted_emits_no_warning(
    _fake_aws_env: None, caplog: pytest.LogCaptureFixture
) -> None:
    """When the caller omits seed entirely we must stay silent."""
    from agent_guardian.llm.bedrock import BedrockClient as _BC

    _BC._seed_warning_emitted = False
    respx.post(_converse_url_re()).mock(return_value=_happy_response())
    client = BedrockClient(region="us-east-1")
    try:
        with caplog.at_level(logging.DEBUG, logger="agent_guardian.llm.bedrock"):
            await client.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="hi")],
                    model="anthropic.claude-haiku-4-5-v1:0",
                )
            )
        seed_warnings = [r for r in caplog.records if "does not support seed" in r.getMessage()]
        assert seed_warnings == []
    finally:
        await client.aclose()
