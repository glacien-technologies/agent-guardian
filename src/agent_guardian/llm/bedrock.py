"""AWS Bedrock Converse API client (PRD §14.3).

This module ships the production Bedrock provider. The client is built from
three layers:

1. The pure :func:`build_bedrock_payload` / :func:`map_bedrock_response`
   helpers — request/response shaping, no I/O, fully unit-testable. These
   landed in M3 and have not changed.
2. SigV4 signing via :mod:`botocore` (the lean credential-chain + signer
   subset of boto3 — see the ``[aws]`` extra in ``pyproject.toml``).
3. HTTP transport via our existing :class:`httpx.AsyncClient`, which the
   rest of the framework already owns (retry-with-backoff, sandbox, and
   the per-provider concurrency semaphore live on :class:`BaseLLM`).

We deliberately do **not** depend on the full ``boto3`` SDK or
``aioboto3``: botocore's request signer is everything we need, and its
SDK-style client would mean second-guessing the asyncio transport we
already manage. Credentials are resolved through the standard AWS chain
at construction time so misconfiguration fails fast.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import with_backoff
from agent_guardian.logging_setup import log_model_request, log_model_response

_LOG = logging.getLogger(__name__)

# botocore is an optional dependency (``[aws]`` extra) used only by
# the live ``BedrockClient`` for SigV4 signing + credential resolution.
# We import it lazily so the pure ``build_bedrock_payload`` /
# ``map_bedrock_response`` helpers (and the module itself, which is
# unconditionally re-exported from ``agent_guardian.llm``) work without
# the extra installed. The mypy override in ``pyproject.toml`` silences
# the dynamic-typing noise.
_BOTOCORE_IMPORT_ERROR: Exception | None
try:  # pragma: no cover — import guard
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.exceptions import (
        BotoCoreError,
        NoCredentialsError,
        ProfileNotFound,
    )
    from botocore.session import Session as BotocoreSession

    _BOTOCORE_AVAILABLE = True
    _BOTOCORE_IMPORT_ERROR = None
except ImportError as _exc:  # pragma: no cover — import guard
    _BOTOCORE_AVAILABLE = False
    _BOTOCORE_IMPORT_ERROR = _exc
    _LOG.debug("bedrock: botocore not installed (install via [aws] extra): %s", _exc)


__all__ = [
    "BEDROCK_HOST_TEMPLATE",
    "BedrockClient",
    "build_bedrock_payload",
    "map_bedrock_response",
]

BEDROCK_HOST_TEMPLATE = "bedrock-runtime.{region}.amazonaws.com"

_FINISH_REASON_MAP = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "tool_use": "tool_call",
    "guardrail_intervened": "content_filter",
}

# Bedrock returns its error taxonomy in the response body under one of
# ``__type`` / ``message`` / ``Message`` fields. We map the canonical
# names to our provider-agnostic exception hierarchy. Any name not in
# this table falls back to the HTTP-status heuristic in
# ``_raise_for_bedrock_status``.
_ACCESS_DENIED_HINT = (
    "Bedrock model access not enabled. Visit "
    "https://console.aws.amazon.com/bedrock/home -> Model access and "
    "request the Anthropic Claude family for your region."
)


def build_bedrock_payload(request: LLMRequest) -> dict[str, Any]:
    """Convert an :class:`LLMRequest` into a Bedrock Converse request body.

    Pure function — no AWS auth, no I/O. Exposed for direct unit-testing.
    """
    system_parts: list[dict[str, Any]] = []
    messages: list[dict[str, Any]] = []
    for msg in request.messages:
        if msg.role == "system":
            system_parts.append({"text": msg.content})
        else:
            messages.append({"role": msg.role, "content": [{"text": msg.content}]})

    payload: dict[str, Any] = {
        "messages": messages,
        "inferenceConfig": {
            "maxTokens": request.max_tokens,
            "temperature": request.temperature,
        },
    }
    if system_parts:
        payload["system"] = system_parts
    if request.stop is not None:
        payload["inferenceConfig"]["stopSequences"] = list(request.stop)
    return payload


def map_bedrock_response(model: str, data: dict[str, Any]) -> LLMResponse:
    """Map a Bedrock Converse response payload to :class:`LLMResponse`.

    Pure function — exposed for direct unit-testing.
    """
    try:
        message = data["output"]["message"]
        blocks = message.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if "text" in b)
        usage = data.get("usage") or {}
        raw_finish = data.get("stopReason") or "end_turn"
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise LLMResponseFormatError(f"bedrock: malformed response: {exc}") from exc
    prompt_tokens = int(usage.get("inputTokens", 0))
    completion_tokens = int(usage.get("outputTokens", 0))
    total_tokens = int(usage.get("totalTokens", prompt_tokens + completion_tokens))
    return LLMResponse(
        text=text,
        model=model,
        provider="bedrock",
        usage=LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        ),
        finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
        raw=data,
    )


def _extract_bedrock_error(resp: httpx.Response) -> tuple[str, str]:
    """Return ``(error_code, message)`` from a Bedrock error response.

    Bedrock surfaces typed errors in the response body via the
    ``__type`` field (sometimes namespaced as ``com.amazon.coral.service#X``).
    Falls back to the raw status line if the body is not JSON.
    """
    try:
        body = resp.json()
    except ValueError as exc:
        _LOG.debug("bedrock: error body is not JSON (%s); using raw text", exc)
        return ("", resp.text or "")
    if not isinstance(body, dict):
        return ("", str(body))
    raw_type = body.get("__type") or body.get("code") or ""
    # ``com.amazon.coral.service#AccessDeniedException`` -> ``AccessDeniedException``
    if isinstance(raw_type, str) and "#" in raw_type:
        raw_type = raw_type.split("#", 1)[1]
    message = body.get("message") or body.get("Message") or body.get("errorMessage") or ""
    return (str(raw_type), str(message))


def _raise_for_bedrock_status(resp: httpx.Response) -> None:
    """Map a Bedrock HTTP response to our error hierarchy.

    Bedrock returns its typed error codes in the response body (see
    :func:`_extract_bedrock_error`) and uses a few different HTTP status
    codes for the same logical condition (``AccessDeniedException`` ships
    as 400 in some regions, 403 in others). We prefer the body-level
    type when present and fall back to the HTTP status otherwise.
    """
    if resp.status_code < 400:
        return

    code, message = _extract_bedrock_error(resp)
    detail = f"{code}: {message}" if code else f"{resp.status_code} {resp.text}"

    # Body-level typed errors take precedence.
    if code == "AccessDeniedException":
        raise LLMAuthError(f"bedrock: {_ACCESS_DENIED_HINT} ({message})")
    if code in ("ThrottlingException", "TooManyRequestsException", "ServiceQuotaExceededException"):
        retry_after_hdr = resp.headers.get("retry-after")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "bedrock: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("bedrock rate limited (code=%s retry_after=%s)", code, retry_after)
        raise LLMRateLimitError(f"bedrock: rate limited ({detail})", retry_after=retry_after)
    if code == "ValidationException":
        raise LLMPermanentError(f"bedrock: validation failed: {detail}")
    if code == "ModelTimeoutException":
        raise LLMTimeoutError(f"bedrock: model timeout: {detail}")
    if code in (
        "ServiceUnavailableException",
        "ModelStreamErrorException",
        "InternalServerException",
    ):
        raise LLMTransientError(f"bedrock: transient: {detail}")
    if code == "ResourceNotFoundException":
        raise LLMPermanentError(f"bedrock: model not found: {detail}")
    if code in (
        "UnrecognizedClientException",
        "InvalidSignatureException",
        "ExpiredTokenException",
    ):
        raise LLMAuthError(f"bedrock: credential rejected: {detail}")

    # HTTP-status fallback for un-typed errors.
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"bedrock: auth failed: {detail}")
    if resp.status_code == 429:
        raise LLMRateLimitError(f"bedrock: rate limited: {detail}")
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"bedrock: transient {resp.status_code}: {detail}")
    raise LLMPermanentError(f"bedrock: {resp.status_code} {detail}")


class BedrockClient(BaseLLM):
    """AWS Bedrock Converse API provider client.

    Authentication uses the standard AWS credential chain (env vars,
    ``~/.aws/credentials``, IAM role, container creds, …) via
    :mod:`botocore`. Credentials are resolved at construction so a
    misconfigured operator gets a clear error before any scan tokens
    are spent.
    """

    provider = "bedrock"
    default_max_concurrency = 5

    # Class-level flag so the "seed not supported" debug warning is emitted
    # at most once per process — protects log volume during long swarm runs
    # where every replay would otherwise re-log the same notice.
    _seed_warning_emitted: bool = False

    def _maybe_warn_seed_ignored(self, request: LLMRequest) -> None:
        if request.seed is None:
            return
        if BedrockClient._seed_warning_emitted:
            return
        BedrockClient._seed_warning_emitted = True
        _LOG.debug(
            "bedrock: provider does not support seed; ignoring "
            "(deterministic replay unavailable for this provider)"
        )

    def __init__(
        self,
        *,
        region: str | None = None,
        profile: str | None = None,
        timeout_seconds: float = 60.0,
        max_concurrency: int | None = None,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not _BOTOCORE_AVAILABLE:
            raise LLMAuthError(
                "bedrock: botocore is not installed. Install the AWS extra: "
                "'pip install agent-guardian[aws]' or 'uv sync --extra aws'. "
                f"(import error: {_BOTOCORE_IMPORT_ERROR})"
            )
        resolved_region = (
            region
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "us-east-1"
        )
        resolved_base_url = (
            base_url or f"https://{BEDROCK_HOST_TEMPLATE.format(region=resolved_region)}"
        )
        # ``api_key`` is unused for SigV4 — credentials come from the chain.
        super().__init__(
            api_key="",
            base_url=resolved_base_url,
            timeout_seconds=timeout_seconds,
            max_concurrency=max_concurrency,
            client=client,
        )
        self.region = resolved_region
        self._profile = profile

        try:
            self._botocore_session = BotocoreSession(profile=profile)
        except ProfileNotFound as exc:
            raise LLMAuthError(f"bedrock: AWS profile not found: {exc}") from exc

        # Override the region on the session so AWS_REGION env semantics
        # match what botocore would see for any downstream signer call.
        self._botocore_session.set_config_variable("region", resolved_region)

        try:
            self._credentials = self._botocore_session.get_credentials()
        except (NoCredentialsError, BotoCoreError) as exc:
            raise LLMAuthError(f"bedrock: AWS credential resolution failed: {exc}") from exc

        if self._credentials is None:
            raise LLMAuthError(
                "bedrock: no AWS credentials found. Set AWS_ACCESS_KEY_ID + "
                "AWS_SECRET_ACCESS_KEY in the environment, configure "
                "~/.aws/credentials, or run from an IAM-role-enabled host."
            )
        self._signer = SigV4Auth(self._credentials, "bedrock", resolved_region)

    def host(self) -> str:
        return BEDROCK_HOST_TEMPLATE.format(region=self.region)

    def pricing_model_spec(self, request: LLMRequest) -> str:
        """Return the provider-qualified Bedrock model used for pricing."""
        model = request.model
        if model.startswith("bedrock:"):
            model = model[len("bedrock:") :]
        return f"bedrock:{model}"

    def _build_signed_headers(self, url: str, body_json: str) -> dict[str, str]:
        """Sign the request body for ``url`` and return the headers to send.

        Builds a fresh :class:`AWSRequest` per call so the SigV4 timestamp
        (``X-Amz-Date``) is current — Bedrock rejects signatures more
        than ~15 minutes old.

        Credential refresh happens lazily inside ``add_auth`` (for SSO,
        web-identity, container, and IMDS providers). Any failure during
        that refresh — most commonly an expired SSO token — surfaces as
        a botocore exception we re-raise as :class:`LLMAuthError` so the
        rest of the framework sees a stable error type.
        """
        aws_request = AWSRequest(
            method="POST",
            url=url,
            data=body_json,
            headers={"Content-Type": "application/json"},
        )
        try:
            self._signer.add_auth(aws_request)
        except (NoCredentialsError, BotoCoreError) as exc:
            raise LLMAuthError(f"bedrock: AWS credential refresh failed: {exc}") from exc
        # ``aws_request.headers`` is a botocore HTTPHeaders mapping; httpx
        # accepts any Mapping[str, str] so we coerce to a plain dict.
        return {str(k): str(v) for k, v in aws_request.headers.items()}

    async def _send(self, request: LLMRequest) -> LLMResponse:
        self._maybe_warn_seed_ignored(request)
        body = build_bedrock_payload(request)
        body_json = json.dumps(body)
        # Strip a ``bedrock:`` provider prefix if the caller passed the
        # spec form (e.g. ``bedrock:global.anthropic.claude-opus-4-6-v1``)
        # rather than the bare model id. Without this strip the request
        # URL becomes ``/model/bedrock:global.anthropic.../converse`` and
        # Bedrock responds 400 "invalid model identifier".
        bedrock_model_id = request.model
        if bedrock_model_id.startswith("bedrock:"):
            bedrock_model_id = bedrock_model_id[len("bedrock:") :]
        url = f"{(self.base_url or '').rstrip('/')}/model/{bedrock_model_id}/converse"
        headers = self._build_signed_headers(url, body_json)
        # One coherent block per call (provider+model stamped once on the INFO
        # narration line emitted here); the full request out lands at DEBUG.
        # ``seed`` is not forwarded by this provider (see _maybe_warn_seed_ignored)
        # so we don't log it as if it were honoured.
        log_model_request(
            _LOG,
            provider="bedrock",
            model=bedrock_model_id,
            n_messages=len(request.messages),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            request_body=body,
            messages=request.messages,
        )
        try:
            resp = await self._client.post(url, content=body_json, headers=headers)
        except httpx.TimeoutException as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTimeoutError(f"bedrock: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMTransientError(f"bedrock: network error: {exc}") from exc
        _raise_for_bedrock_status(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            log_model_response(_LOG, error=exc)
            raise LLMResponseFormatError(f"bedrock: invalid JSON: {exc}") from exc
        # Pass the unprefixed Bedrock model id (without the optional
        # ``bedrock:`` provider tag) so the resulting LLMResponse.model
        # matches what Bedrock itself reports — downstream cost lookup
        # and receipts key off the bare id, not the spec string.
        response = map_bedrock_response(bedrock_model_id, data)
        # Response in — full text + usage + finish; a content_filter finish is
        # surfaced at WARNING by the helper rather than swallowed.
        log_model_response(
            _LOG,
            response_text=response.text,
            usage=response.usage,
            finish_reason=response.finish_reason,
        )
        return response

    async def complete(self, request: LLMRequest) -> LLMResponse:
        async with self._semaphore:
            return await with_backoff(lambda: self._send(request))
