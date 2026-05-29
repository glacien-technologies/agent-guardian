"""HTTP transport (Stage 1A).

A :class:`HttpTransport` is the production transport over a hosted HTTP/JSON
target. It is built from **primitives** (endpoint, request template, response
jsonpaths, auth provider) — never from a Contract; the contract→transport
wiring is a later stage and lives elsewhere, preserving the decoupling rule.

Request shaping is done by :func:`agent_guardian.transports.templating.render_body`;
response parsing pulls fields out with the project's dotted-JSONPath walker
:func:`agent_guardian.adapters.http_shapes.generic_shape.walk_jsonpath`
(``output_path``, ``error_path``, ``tool_call_path``). The actual HTTP send is
delegated to :meth:`HttpAdapter.send_raw`, the public seam that gives us the
shared httpx client, concurrency semaphore, retry/backoff and HTTP→LLM error
mapping — without the adapter's opinionated provider shaping.

:meth:`HttpTransport.send` never raises for a transport fault: it catches the
LLM error hierarchy and returns a :class:`Response` whose ``error`` is the
mapped :class:`TransportError`. An ``error_path`` that matches on an otherwise
successful 200 yields a :class:`TransportErrorCategory.BLOCKED` fault (the
target refused/blocked the request at the application layer).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath
from agent_guardian.llm.errors import LLMError, LLMResponseFormatError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import Request, Response, TokenUsage, ToolCall, Transport
from agent_guardian.transports.errors import TransportError, TransportErrorCategory, map_llm_error
from agent_guardian.transports.templating import render_body

__all__ = ["HttpTransport"]

_LOG = logging.getLogger(__name__)

_DEFAULT_TEMPLATE = '{"input": "{{ prompt }}"}'


class HttpTransport(Transport):
    """Production HTTP transport, built from primitives (not a Contract)."""

    def __init__(
        self,
        *,
        endpoint: str,
        request_template: str = _DEFAULT_TEMPLATE,
        output_path: str = "$.output.text",
        error_path: str | None = None,
        tool_call_path: str | None = None,
        tool_call_name_path: str = "$.name",
        tool_call_args_path: str = "$.arguments",
        session_path: str | None = None,
        usage_prompt_tokens_path: str | None = None,
        usage_completion_tokens_path: str | None = None,
        usage_total_tokens_path: str | None = None,
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        client: httpx.AsyncClient | None = None,
        adapter: HttpAdapter | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("HttpTransport requires a non-empty endpoint")
        self._endpoint = endpoint
        self._request_template = request_template
        self._output_path = output_path
        self._error_path = error_path
        self._tool_call_path = tool_call_path
        self._tool_call_name_path = tool_call_name_path
        self._tool_call_args_path = tool_call_args_path
        self._session_path = session_path
        self._usage_prompt_path = usage_prompt_tokens_path
        self._usage_completion_path = usage_completion_tokens_path
        self._usage_total_path = usage_total_tokens_path
        self._auth: AuthProvider = auth or NoAuth()
        self._base_headers = dict(base_headers or {})

        # Wrap (or accept an injected) HttpAdapter. We always use the "generic"
        # shape because we never invoke the adapter's opinionated ``call()`` —
        # only the raw ``send_raw`` seam — so the shape is irrelevant here.
        self._owns_adapter = adapter is None
        self._adapter = adapter or HttpAdapter(
            endpoint,
            shape="generic",
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            max_concurrency=max_concurrency,
            client=client,
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def _build_body(self, request: Request) -> dict[str, Any]:
        return render_body(
            self._request_template,
            prompt=request.prompt,
            session=request.session,
            conversation=request.conversation,
        )

    async def _build_headers(self, body: dict[str, Any]) -> tuple[dict[str, str], AuthContext]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        headers.update(self._base_headers)
        ctx = AuthContext(method="POST", url=self._endpoint, headers=headers)
        await self._auth.apply(ctx)
        return ctx.headers, ctx

    def _extract_int(self, data: dict[str, Any], path: str | None) -> int:
        if path is None:
            return 0
        value = walk_jsonpath(data, path)
        if isinstance(value, bool):
            return 0
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        return 0

    def _extract_usage(self, data: dict[str, Any]) -> TokenUsage:
        return TokenUsage(
            prompt_tokens=self._extract_int(data, self._usage_prompt_path),
            completion_tokens=self._extract_int(data, self._usage_completion_path),
            total_tokens=self._extract_int(data, self._usage_total_path),
        )

    def _extract_tool_calls(self, data: dict[str, Any]) -> tuple[ToolCall, ...]:
        if self._tool_call_path is None:
            return ()
        raw = walk_jsonpath(data, self._tool_call_path)
        if raw is None:
            return ()
        items = raw if isinstance(raw, list) else [raw]
        calls: list[ToolCall] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = walk_jsonpath(item, self._tool_call_name_path)
            args = walk_jsonpath(item, self._tool_call_args_path)
            calls.append(
                ToolCall(
                    name=str(name) if name is not None else "",
                    arguments=args if isinstance(args, dict) else {},
                    raw=item,
                )
            )
        return tuple(calls)

    def _parse_response(self, data: dict[str, Any]) -> Response:
        """Parse a successful 200 body. Raises on missing output / blocked."""
        # Application-level block/refusal expressed via error_path.
        if self._error_path is not None:
            blocked = walk_jsonpath(data, self._error_path)
            if blocked is not None and blocked != "" and blocked is not False:
                raise _BlockedError(str(blocked))

        text = walk_jsonpath(data, self._output_path)
        if text is None:
            raise LLMResponseFormatError(
                f"http transport: output_path {self._output_path!r} produced no value"
            )

        session: str | None = None
        if self._session_path is not None:
            session_value = walk_jsonpath(data, self._session_path)
            if session_value is not None:
                session = str(session_value)

        return Response(
            text=str(text),
            tool_calls=self._extract_tool_calls(data),
            usage=self._extract_usage(data),
            session=session,
            raw=data,
        )

    async def send(self, request: Request) -> Response:
        """Send one turn, returning a :class:`Response` (never raises for faults)."""
        try:
            body = self._build_body(request)
        except LLMError as exc:
            _LOG.debug("http transport: request body build failed (%s)", exc)
            return Response(error=map_llm_error(exc))

        try:
            headers, _ctx = await self._build_headers(body)
            data = await self._adapter.send_raw(body, headers)
            return self._parse_response(data)
        except _BlockedError as exc:
            _LOG.debug("http transport: target blocked the request (%s)", exc)
            return Response(
                error=TransportError(TransportErrorCategory.BLOCKED, str(exc)),
                raw=None,
            )
        except LLMError as exc:
            _LOG.debug("http transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    async def aclose(self) -> None:
        if self._owns_adapter:
            await self._adapter.aclose()


class _BlockedError(Exception):
    """Internal signal: a 200 response whose error_path matched (blocked)."""
