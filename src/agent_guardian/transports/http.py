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

TLS is configurable via ``verify``: the default ``True`` does full certificate
verification; a path string pins a private CA bundle; ``False`` disables
verification entirely (insecure — for self-signed / dev targets). The
contract→transport factory lowers ``transport.tls.{ca_bundle,insecure}`` onto
this parameter.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, ClassVar, Literal

import httpx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath
from agent_guardian.llm.errors import LLMError, LLMResponseFormatError
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    TokenUsage,
    ToolCall,
    Transport,
)
from agent_guardian.transports.errors import TransportError, TransportErrorCategory, map_llm_error
from agent_guardian.transports.templating import render_body

__all__ = ["HttpTransport"]

_LOG = logging.getLogger(__name__)

_DEFAULT_TEMPLATE = '{"input": "{{ prompt }}"}'

# Where an outbound server-session id may be placed on a request.
SessionSendIn = Literal["header", "query", "body"]


def _auth_scheme_name(auth: AuthProvider) -> str | None:
    """Derive a readable auth-scheme label from a provider instance.

    ``NoAuth`` reports ``None`` (unauthenticated); every other provider reports
    its class name with a trailing ``Auth`` stripped (e.g. ``BearerAuth`` →
    ``"Bearer"``). This avoids requiring every provider to carry a ``scheme``
    attribute while still giving :meth:`HttpTransport.describe` a useful label.
    """
    if isinstance(auth, NoAuth):
        return None
    name = type(auth).__name__
    return name[:-4] if name.endswith("Auth") else name


class HttpTransport(Transport):
    """Production HTTP transport, built from primitives (not a Contract)."""

    kind: ClassVar[str] = "http"

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
        session_send_in: SessionSendIn | None = None,
        session_send_name: str | None = None,
        usage_prompt_tokens_path: str | None = None,
        usage_completion_tokens_path: str | None = None,
        usage_total_tokens_path: str | None = None,
        stream: bool = False,
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        max_concurrency: int = 5,
        verify: bool | str = True,
        client: httpx.AsyncClient | None = None,
        adapter: HttpAdapter | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("HttpTransport requires a non-empty endpoint")
        if session_send_in is not None and not session_send_name:
            raise ValueError(
                "HttpTransport: session_send_name is required when session_send_in is set"
            )
        self._endpoint = endpoint
        self._request_template = request_template
        self._output_path = output_path
        self._error_path = error_path
        self._tool_call_path = tool_call_path
        self._tool_call_name_path = tool_call_name_path
        self._tool_call_args_path = tool_call_args_path
        self._session_path = session_path
        self._session_send_in = session_send_in
        self._session_send_name = session_send_name
        self._usage_prompt_path = usage_prompt_tokens_path
        self._usage_completion_path = usage_completion_tokens_path
        self._usage_total_path = usage_total_tokens_path
        self._stream = stream
        self._auth: AuthProvider = auth or NoAuth()
        self._base_headers = dict(base_headers or {})

        # Wrap (or accept an injected) HttpAdapter. We always use the "generic"
        # shape because we never invoke the adapter's opinionated ``call()`` —
        # only the raw ``send_raw`` seam — so the shape is irrelevant here.
        self._owns_adapter = adapter is None
        # ``verify`` governs TLS: True (default), a CA-bundle path, or False
        # (insecure — no cert verification). It is applied only to a client this
        # transport builds; an injected ``client`` carries its own TLS config.
        self._adapter = adapter or HttpAdapter(
            endpoint,
            shape="generic",
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            max_concurrency=max_concurrency,
            verify=verify,
            client=client,
        )
        # Serializes the per-request endpoint swap used only for "query"
        # outbound session placement (the adapter posts to a fixed endpoint).
        self._query_lock = asyncio.Lock()

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def _build_body(self, request: Request) -> dict[str, Any]:
        body = render_body(
            self._request_template,
            prompt=request.prompt,
            session=request.session,
            conversation=request.conversation,
        )
        # Outbound session-id placement (body): set a top-level key IN ADDITION
        # to whatever the template already rendered.
        if (
            self._session_send_in == "body"
            and self._session_send_name is not None
            and request.session is not None
        ):
            body[self._session_send_name] = request.session
        return body

    def _endpoint_for(self, request: Request) -> str:
        """Endpoint for this request, with the session id merged into the query
        string when outbound placement is ``"query"``."""
        if (
            self._session_send_in == "query"
            and self._session_send_name is not None
            and request.session is not None
        ):
            url = httpx.URL(self._endpoint)
            url = url.copy_merge_params({self._session_send_name: request.session})
            return str(url)
        return self._endpoint

    async def _build_headers(
        self, request: Request, url: str
    ) -> tuple[dict[str, str], AuthContext]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        headers.update(self._base_headers)
        # Outbound session-id placement (header): set IN ADDITION to base headers
        # and before auth so an auth provider could sign over it if it wished.
        if (
            self._session_send_in == "header"
            and self._session_send_name is not None
            and request.session is not None
        ):
            headers[self._session_send_name] = request.session
        ctx = AuthContext(method="POST", url=url, headers=headers)
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

    async def _send_raw(
        self, body: dict[str, Any], headers: dict[str, str], url: str
    ) -> dict[str, Any]:
        """POST via the adapter at ``url``.

        For the common case ``url`` equals the adapter's fixed endpoint and we
        delegate straight to :meth:`HttpAdapter.send_raw`. Outbound ``"query"``
        session placement produces a per-request URL; since the adapter posts to
        a fixed endpoint we temporarily swap it under a lock (serialising only
        query-mode sends) and restore it afterwards. ``header``/``body`` modes
        never take this path.
        """
        if url == self._endpoint:
            return await self._adapter.send_raw(body, headers)
        async with self._query_lock:
            original = self._adapter._endpoint
            self._adapter._endpoint = url
            try:
                return await self._adapter.send_raw(body, headers)
            finally:
                self._adapter._endpoint = original

    async def send(self, request: Request) -> Response:
        """Send one turn, returning a :class:`Response` (never raises for faults)."""
        try:
            body = self._build_body(request)
        except LLMError as exc:
            _LOG.debug("http transport: request body build failed (%s)", exc)
            return Response(error=map_llm_error(exc))

        url = self._endpoint_for(request)
        try:
            headers, _ctx = await self._build_headers(request, url)
            data = await self._send_raw(body, headers, url)
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

    def describe(self) -> CapabilityReport:
        """Report this HTTP transport's static capabilities.

        ``streaming`` reflects whether a streaming config is set; ``supports_tools``
        whether a ``tool_call_path`` is configured; ``auth_scheme`` is derived from
        the auth provider (``None`` for unauthenticated targets). ``session_modes``
        lists the modes this transport can support — it can always run stateless or
        replay client history; server-session requires a ``session_path`` to capture
        the id and/or an outbound placement to replay it.
        """
        session_modes: list[str] = ["stateless", "client_history"]
        if self._session_path is not None or self._session_send_in is not None:
            session_modes.insert(1, "server_session")
        return CapabilityReport(
            kind=self.kind,
            streaming=self._stream,
            supports_tools=self._tool_call_path is not None,
            session_modes=tuple(session_modes),
            auth_scheme=_auth_scheme_name(self._auth),
            endpoint=self._endpoint,
        )

    async def aclose(self) -> None:
        """Release transport resources, cascading to the auth provider.

        Closes the owned :class:`HttpAdapter` (if this transport built it) and
        then awaits :meth:`AuthProvider.aclose` so any token-fetch client the
        provider holds (OAuth2 / Entra / MCP OAuth) cannot leak. The auth
        ``aclose`` runs in the ``finally`` so an adapter-close error does not
        suppress provider cleanup.
        """
        try:
            if self._owns_adapter:
                await self._adapter.aclose()
        finally:
            await self._auth.aclose()


class _BlockedError(Exception):
    """Internal signal: a 200 response whose error_path matched (blocked)."""
