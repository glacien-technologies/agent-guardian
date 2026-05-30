"""OpenAI Responses API transport (Stage 2).

The Responses API (``POST {base_url}/responses``) is OpenAI's stateful agent
endpoint. A turn is shaped as ``{"model": ..., "input": <prompt>, "store": ...}``
and the reply text is read from the convenience ``output_text`` field, falling
back to walking ``output[].content[].text`` blocks when the convenience field
is absent.

**Session model — server_session via ``previous_response_id``.** Every response
carries an ``id``; we surface it as :attr:`Response.session`. The
:class:`~agent_guardian.transports.session.SessionMachine` (SERVER_SESSION mode)
captures that id and replays it on the next :class:`Request` as
``request.session`` — which we forward as ``previous_response_id`` so the server
threads the conversation. We do *not* resend prior turns as history.

**Auth.** A :class:`~agent_guardian.transports.auth.base.AuthProvider` (Bearer,
in practice) is injected by the factory in a later phase; we never construct
credentials here.

Like every :class:`~agent_guardian.transports.base.Transport`, :meth:`send`
never raises for a transport fault — it catches the LLM error hierarchy and
returns a :class:`Response` whose ``error`` is the mapped
:class:`~agent_guardian.transports.errors.TransportError`.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import httpx

from agent_guardian.adapters.http import HttpAdapter
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

__all__ = ["OpenAiResponsesTransport"]

_LOG = logging.getLogger(__name__)


class OpenAiResponsesTransport(Transport):
    """OpenAI Responses API transport (``server_session`` via previous_response_id)."""

    kind: ClassVar[str] = "openai_responses"

    def __init__(
        self,
        *,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        store: bool = True,
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
        adapter: HttpAdapter | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("OpenAiResponsesTransport requires a non-empty base_url")
        self._endpoint = f"{base_url.rstrip('/')}/responses"
        self._model = model
        self._store = store
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
            session_modes=("server_session",),
            auth_scheme="bearer",
            endpoint=self._endpoint,
        )

    def _build_body(self, request: Request) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self._model,
            "input": request.prompt,
            "store": self._store,
        }
        # server_session: replay the previously captured response id.
        if request.session is not None:
            body["previous_response_id"] = request.session
        return body

    async def _build_headers(self, body: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        headers.update(self._base_headers)
        ctx = AuthContext(method="POST", url=self._endpoint, headers=headers)
        await self._auth.apply(ctx)
        return ctx.headers

    @staticmethod
    def _extract_text(data: dict[str, Any]) -> str:
        # Convenience field first.
        convenience = data.get("output_text")
        if isinstance(convenience, str):
            return convenience
        # Otherwise walk output[].content[].text and concatenate text parts.
        output = data.get("output")
        if isinstance(output, list):
            parts: list[str] = []
            for item in output:
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if not isinstance(content, list):
                    continue
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text")
                        if isinstance(text, str):
                            parts.append(text)
            if parts:
                return "".join(parts)
        raise LLMResponseFormatError(
            "openai_responses: no output_text and no output[].content[].text blocks"
        )

    @staticmethod
    def _extract_usage(data: dict[str, Any]) -> TokenUsage:
        usage = data.get("usage")
        if not isinstance(usage, dict):
            return TokenUsage()
        return TokenUsage(
            prompt_tokens=_as_int(usage.get("input_tokens")),
            completion_tokens=_as_int(usage.get("output_tokens")),
            total_tokens=_as_int(usage.get("total_tokens")),
        )

    def _parse_response(self, data: dict[str, Any]) -> Response:
        text = self._extract_text(data)
        session_id = data.get("id")
        session = str(session_id) if session_id is not None else None
        return Response(
            text=text,
            usage=self._extract_usage(data),
            session=session,
            raw=data,
        )

    async def send(self, request: Request) -> Response:
        try:
            body = self._build_body(request)
            headers = await self._build_headers(body)
            data = await self._adapter.send_raw(body, headers)
            return self._parse_response(data)
        except LLMError as exc:
            _LOG.debug("openai_responses transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    async def aclose(self) -> None:
        """Release transport resources, cascading to the auth provider."""
        try:
            if self._owns_adapter:
                await self._adapter.aclose()
        finally:
            await self._auth.aclose()


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return 0
