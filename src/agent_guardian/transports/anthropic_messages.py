"""Anthropic Messages API transport (Stage 2).

The Messages API (``POST {base_url}/messages``) is stateless: the client owns
the transcript and resends it on every turn. A turn is shaped as
``{"model": ..., "max_tokens": ..., "messages": [...]}`` where ``messages`` is
built from :attr:`Request.conversation` (oldest-first) plus the current
:attr:`Request.prompt` — the ``client_history`` pattern. The
:class:`~agent_guardian.transports.session.SessionMachine` (CLIENT_HISTORY mode)
accumulates the ``(user, assistant)`` pairs and threads them back in via
``conversation`` on each turn; this transport carries no server session token.

Reply text is concatenated from ``content[].text`` blocks (reusing
:func:`agent_guardian.adapters.http_shapes.anthropic_shape.extract_response_text`);
``stop_reason`` is retained on ``raw``. Token usage is read from
``usage.input_tokens`` / ``usage.output_tokens``.

**Auth.** An :class:`~agent_guardian.transports.auth.base.AuthProvider`
(``x-api-key`` ApiKeyAuth, in practice) is injected by the factory. The required
``anthropic-version`` header is set here.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import httpx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.http_shapes.anthropic_shape import (
    extract_response_text as anthropic_extract_text,
)
from agent_guardian.llm.errors import LLMError, LLMResponseFormatError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    TokenUsage,
    Transport,
)
from agent_guardian.transports.errors import map_llm_error

__all__ = ["AnthropicMessagesTransport"]

_LOG = logging.getLogger(__name__)

_DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicMessagesTransport(Transport):
    """Anthropic Messages API transport (``client_history`` over a stateless API)."""

    kind: ClassVar[str] = "anthropic_messages"

    def __init__(
        self,
        *,
        base_url: str = "https://api.anthropic.com/v1",
        model: str = "claude-3-5-sonnet-latest",
        max_tokens: int = 1024,
        anthropic_version: str = _DEFAULT_ANTHROPIC_VERSION,
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
        adapter: HttpAdapter | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("AnthropicMessagesTransport requires a non-empty base_url")
        if max_tokens <= 0:
            raise ValueError("AnthropicMessagesTransport max_tokens must be > 0")
        self._endpoint = f"{base_url.rstrip('/')}/messages"
        self._model = model
        self._max_tokens = max_tokens
        self._anthropic_version = anthropic_version
        self._auth: AuthProvider = auth or NoAuth()
        self._base_headers = dict(base_headers or {})

        self._owns_adapter = adapter is None
        self._adapter = adapter or HttpAdapter(
            self._endpoint,
            shape="generic",
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            max_concurrency=max_concurrency,
            client=client,
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def describe(self) -> CapabilityReport:
        return CapabilityReport(
            kind=self.kind,
            session_modes=("client_history",),
            auth_scheme="api_key",
            endpoint=self._endpoint,
        )

    def _build_messages(self, request: Request) -> list[dict[str, str]]:
        # client_history: prior conversation (oldest-first) then the new prompt.
        messages: list[dict[str, str]] = [
            {"role": msg.role, "content": msg.content} for msg in request.conversation
        ]
        messages.append({"role": "user", "content": request.prompt})
        return messages

    def _build_body(self, request: Request) -> dict[str, Any]:
        return {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": self._build_messages(request),
        }

    async def _build_headers(self, body: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
            "anthropic-version": self._anthropic_version,
        }
        headers.update(self._base_headers)
        ctx = AuthContext(method="POST", url=self._endpoint, headers=headers)
        await self._auth.apply(ctx)
        return ctx.headers

    @staticmethod
    def _extract_usage(data: dict[str, Any]) -> TokenUsage:
        usage = data.get("usage")
        if not isinstance(usage, dict):
            return TokenUsage()
        prompt = _as_int(usage.get("input_tokens"))
        completion = _as_int(usage.get("output_tokens"))
        return TokenUsage(
            prompt_tokens=prompt,
            completion_tokens=completion,
            total_tokens=prompt + completion,
        )

    def _parse_response(self, data: dict[str, Any]) -> Response:
        try:
            text = anthropic_extract_text(data)
        except ValueError as exc:
            raise LLMResponseFormatError(str(exc)) from exc
        return Response(
            text=text,
            usage=self._extract_usage(data),
            raw=data,
        )

    async def send(self, request: Request) -> Response:
        try:
            body = self._build_body(request)
            headers = await self._build_headers(body)
            data = await self._adapter.send_raw(body, headers)
            return self._parse_response(data)
        except LLMError as exc:
            _LOG.debug("anthropic_messages transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    async def aclose(self) -> None:
        if self._owns_adapter:
            await self._adapter.aclose()


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return 0
