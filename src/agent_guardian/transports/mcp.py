"""MCP transport — a JSON-RPC 2.0 client over Streamable HTTP (Stage 3).

The Model Context Protocol exposes a *tool surface*: a server advertises a set
of callable tools (``tools/list``) and the client invokes them (``tools/call``)
over JSON-RPC 2.0. :class:`McpTransport` speaks that protocol from
**primitives** (an endpoint, an optional entry tool, an auth provider) — never
from a Contract; the contract→transport wiring lives in the factory layer,
preserving the decoupling rule that the rest of the transport package follows.

Three JSON-RPC methods carry the conversation:

* ``initialize`` — the handshake. The client announces its protocol version,
  client info and capabilities; the server returns its capabilities and *may*
  set an ``Mcp-Session-Id`` response header. When present we capture that id and
  replay it as a request header on every later call so the server can resume the
  same session (this is the MCP ``server_session`` mode).
* ``tools/list`` — discovery. Returns ``{tools: [{name, description,
  inputSchema}]}``; we cache both the names (for tool selection / RoE gating)
  and the full schemas (for :meth:`describe`).
* ``tools/call`` — invocation. ``{name, arguments}`` → ``{content: [{type:
  "text", text: ...}], isError?}``.

Resilience mirrors :class:`agent_guardian.transports.http.HttpTransport`: every
RPC is wrapped in :func:`agent_guardian.llm.retry.with_backoff`, HTTP status
codes are folded onto the LLM error hierarchy by a ``_raise_for_status``-style
check, and httpx faults are mapped to a :class:`TransportError` via
:func:`agent_guardian.transports.errors.map_llm_error`. :meth:`send` never
raises for a transport fault — it returns a :class:`Response` whose ``error`` is
populated instead.

The **live tool-block** is the security primitive of this transport. Before any
``tools/call`` the chosen tool name is passed through an injected ``tool_gate``
(the RoE chokepoint). If the gate returns ``False`` we *do not* contact the
server at all: we return a benign note plus a recorded :class:`ToolCall` so a
destructive tool (``delete_everything``, ``rm_rf``, …) is suppressed *before* it
executes, not merely flagged after the fact.

Authorization follows the MCP spec: bearer credentials are applied through the
:class:`AuthProvider` into the ``Authorization`` **header** only — never a query
string.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, ClassVar

import httpx

from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import with_backoff
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    ToolCall,
    Transport,
)
from agent_guardian.transports.errors import TransportError, TransportErrorCategory, map_llm_error

__all__ = ["McpTransport"]

_LOG = logging.getLogger(__name__)

# Protocol version we advertise in the ``initialize`` handshake. MCP uses a
# date-stamped version string; servers negotiate down if they only speak older.
_PROTOCOL_VERSION = "2025-06-18"

# Identity announced to the server in ``initialize``.
_CLIENT_NAME = "agent-guardian"
_CLIENT_VERSION = "0"

# Header the server uses to hand us a resumable session id (and that we replay).
_SESSION_HEADER = "Mcp-Session-Id"

# The MCP server-session mode label surfaced in CapabilityReport.session_modes.
_SERVER_SESSION_MODE = "server_session"

# Category for a protocol-level fault (a JSON-RPC error / no-tools server). The
# Stage spec calls for a ``PROTOCOL`` category; resolve it dynamically so this
# module works whether or not the core taxonomy carries that member yet, falling
# back to ``PERMANENT`` (a JSON-RPC error is a non-retryable server-side fault).
_PROTOCOL_FAULT: TransportErrorCategory = getattr(
    TransportErrorCategory, "PROTOCOL", TransportErrorCategory.PERMANENT
)


def _auth_scheme_name(auth: AuthProvider) -> str | None:
    """Derive a readable auth-scheme label from a provider instance.

    Mirrors the helper in :mod:`agent_guardian.transports.http`: ``NoAuth``
    reports ``None``; every other provider reports its class name with a
    trailing ``Auth`` stripped (e.g. ``BearerAuth`` → ``"Bearer"``).
    """
    if isinstance(auth, NoAuth):
        return None
    name = type(auth).__name__
    return name[:-4] if name.endswith("Auth") else name


def _raise_for_status(resp: httpx.Response) -> None:
    """Map an HTTP response status onto our LLM error hierarchy.

    A copy of :func:`agent_guardian.adapters.http._raise_for_status` kept local
    so the MCP transport can POST raw JSON-RPC envelopes (and read the
    ``Mcp-Session-Id`` response header) without routing through the adapter's
    fixed request/response shaping.
    """
    if resp.status_code < 400:
        return
    body_preview = resp.text[:512]
    if resp.status_code in (401, 403):
        raise LLMAuthError(f"mcp: auth failed: {resp.status_code} {body_preview}")
    if resp.status_code == 429:
        retry_after_hdr = resp.headers.get("retry-after")
        retry_after: float | None = None
        if retry_after_hdr is not None:
            try:
                retry_after = float(retry_after_hdr)
            except ValueError:
                _LOG.debug(
                    "mcp: unparseable Retry-After header %r — backoff will use default",
                    retry_after_hdr,
                )
                retry_after = None
        _LOG.warning("mcp target 429 rate limited (retry_after=%s)", retry_after)
        raise LLMRateLimitError("mcp: rate limited", retry_after=retry_after)
    if resp.status_code == 408 or resp.status_code >= 500:
        raise LLMTransientError(f"mcp: transient {resp.status_code}: {body_preview}")
    raise LLMPermanentError(f"mcp: {resp.status_code} {body_preview}")


class McpTransport(Transport):
    """JSON-RPC 2.0 client over MCP Streamable HTTP, built from primitives."""

    kind: ClassVar[str] = "mcp"

    def __init__(
        self,
        endpoint: str,
        *,
        entry_tool: str | None = None,
        prompt_argument: str = "input",
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        client: httpx.AsyncClient | None = None,
        tool_gate: Callable[[str], bool] | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("McpTransport requires a non-empty endpoint")
        self._endpoint = endpoint
        self._entry_tool = entry_tool
        self._prompt_argument = prompt_argument
        self._auth: AuthProvider = auth or NoAuth()
        self._base_headers = dict(base_headers or {})
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._tool_gate = tool_gate

        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

        # JSON-RPC request id counter (monotonic, per-transport).
        self._next_id = 0
        # Captured from an ``Mcp-Session-Id`` response header; replayed on later
        # requests so the server can resume the same session.
        self._session_id: str | None = None
        # Server capabilities from the ``initialize`` handshake.
        self._server_capabilities: dict[str, Any] = {}
        # Lazily-populated discovery state.
        self._initialized = False
        self._tools_listed = False
        self._tool_names: tuple[str, ...] = ()
        self._tool_schemas: tuple[dict[str, Any], ...] = ()

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def discovered_tools(self) -> tuple[str, ...]:
        """Tool names discovered via ``tools/list`` (empty until listed)."""
        return self._tool_names

    # ---- JSON-RPC plumbing -------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            # MCP Streamable HTTP servers may answer with JSON or an SSE stream;
            # advertise both so the negotiation is in our favour.
            "accept": "application/json, text/event-stream",
        }
        headers.update(self._base_headers)
        # Replay the resumable session id (header only, per spec).
        if self._session_id is not None:
            headers[_SESSION_HEADER] = self._session_id
        return headers

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """POST a JSON-RPC envelope and return the ``result`` object.

        Applies auth (Authorization header only — never a query string), wraps
        the send in :func:`with_backoff`, maps HTTP/httpx faults onto the LLM
        error hierarchy, captures any ``Mcp-Session-Id`` response header, and
        translates a JSON-RPC ``error`` member into a :class:`TransportError`.

        Raises an :class:`LLMError` subclass or :class:`TransportError` on
        failure; the public :meth:`send` is what swallows these into a
        :class:`Response`.
        """
        self._next_id += 1
        envelope: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params,
        }

        async def _attempt() -> dict[str, Any]:
            headers = self._build_headers()
            ctx = AuthContext(method="POST", url=self._endpoint, headers=headers)
            await self._auth.apply(ctx)
            try:
                resp = await self._client.post(self._endpoint, json=envelope, headers=ctx.headers)
            except httpx.TimeoutException as exc:
                raise LLMTimeoutError(f"mcp: timeout: {exc}") from exc
            except httpx.HTTPError as exc:
                raise LLMTransientError(f"mcp: network error: {exc}") from exc

            _raise_for_status(resp)

            # Capture (or refresh) the resumable session id before parsing.
            session_id = resp.headers.get(_SESSION_HEADER)
            if session_id:
                self._session_id = session_id

            try:
                payload = resp.json()
            except (ValueError, httpx.DecodingError) as exc:
                raise LLMResponseFormatError(f"mcp: invalid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise LLMResponseFormatError(
                    f"mcp: expected JSON object at top level, got {type(payload).__name__}"
                )
            return payload

        payload = await with_backoff(_attempt, max_retries=self._max_retries)

        # A JSON-RPC error member is a protocol-level fault. We surface it as a
        # TransportError so send() can fold it into Response.error. The JSON-RPC
        # error has {code, message, data?}; we keep the message and code.
        error = payload.get("error")
        if isinstance(error, dict):
            raise _JsonRpcError(error)

        result = payload.get("result")
        if not isinstance(result, dict):
            raise LLMResponseFormatError(f"mcp: {method!r} response missing a 'result' object")
        return result

    # ---- MCP methods -------------------------------------------------------

    async def initialize(self) -> dict[str, Any]:
        """Run the JSON-RPC ``initialize`` handshake and store server capabilities."""
        result = await self._rpc(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "clientInfo": {"name": _CLIENT_NAME, "version": _CLIENT_VERSION},
                "capabilities": {},
            },
        )
        capabilities = result.get("capabilities")
        self._server_capabilities = capabilities if isinstance(capabilities, dict) else {}
        self._initialized = True
        return result

    async def list_tools(self) -> tuple[str, ...]:
        """Run ``tools/list``; cache and return the discovered tool names.

        Full tool schemas are retained for :meth:`describe`.
        """
        result = await self._rpc("tools/list", {})
        raw_tools = result.get("tools")
        schemas: list[dict[str, Any]] = []
        names: list[str] = []
        if isinstance(raw_tools, list):
            for item in raw_tools:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    continue
                names.append(name)
                schemas.append(item)
        self._tool_names = tuple(names)
        self._tool_schemas = tuple(schemas)
        self._tools_listed = True
        return self._tool_names

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Run ``tools/call`` for ``name`` with ``arguments``; return the result."""
        return await self._rpc("tools/call", {"name": name, "arguments": arguments})

    # ---- Transport surface -------------------------------------------------

    async def _ensure_discovered(self) -> None:
        """Lazily run the handshake + tool discovery exactly once."""
        if not self._initialized:
            await self.initialize()
        if not self._tools_listed:
            await self.list_tools()

    @staticmethod
    def _extract_text(result: dict[str, Any]) -> str:
        """Concatenate the ``text`` parts of an MCP ``tools/call`` result."""
        content = result.get("content")
        if not isinstance(content, list):
            return ""
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)

    async def send(self, request: Request) -> Response:
        """Send one turn by invoking the entry tool. Never raises for faults.

        On first call this lazily runs ``initialize`` + ``tools/list``. The
        target tool is :attr:`entry_tool` when configured, otherwise the first
        discovered tool. Before invocation the tool name is passed through the
        injected ``tool_gate`` (the RoE chokepoint): if the gate denies it we
        return a benign blocked note *without* contacting the server, so a
        destructive tool is suppressed live.
        """
        try:
            await self._ensure_discovered()
        except _JsonRpcError as exc:
            _LOG.debug("mcp transport: discovery JSON-RPC error (%s)", exc)
            return Response(error=exc.to_transport_error())
        except LLMError as exc:
            _LOG.debug("mcp transport: discovery failed (%s)", exc)
            return Response(error=map_llm_error(exc))

        tool = self._entry_tool or (self._tool_names[0] if self._tool_names else None)
        if tool is None:
            return Response(
                error=TransportError(_PROTOCOL_FAULT, "mcp: server advertised no tools")
            )

        # Live RoE chokepoint: deny destructive tools BEFORE they execute.
        if self._tool_gate is not None and not self._tool_gate(tool):
            _LOG.info("mcp transport: tool %r blocked by RoE (not executed)", tool)
            arguments = {self._prompt_argument: request.prompt}
            return Response(
                text=f"[agent-guardian] tool {tool!r} blocked by RoE; not executed",
                tool_calls=(ToolCall(name=tool, arguments=arguments, raw=None),),
                session=self._session_id,
            )

        arguments = {self._prompt_argument: request.prompt}
        try:
            result = await self.call_tool(tool, arguments)
        except _JsonRpcError as exc:
            _LOG.debug("mcp transport: tools/call JSON-RPC error (%s)", exc)
            return Response(error=exc.to_transport_error())
        except LLMError as exc:
            _LOG.debug("mcp transport: tools/call failed (%s)", exc)
            return Response(error=map_llm_error(exc))

        # An MCP ``tools/call`` may report a tool-level failure via ``isError``.
        if result.get("isError") is True:
            text = self._extract_text(result)
            return Response(
                error=TransportError(
                    TransportErrorCategory.BLOCKED,
                    text or f"mcp: tool {tool!r} reported isError",
                ),
                tool_calls=(ToolCall(name=tool, arguments=arguments, raw=result),),
                session=self._session_id,
                raw=result,
            )

        return Response(
            text=self._extract_text(result),
            tool_calls=(ToolCall(name=tool, arguments=arguments, raw=result),),
            session=self._session_id,
            raw=result,
        )

    def describe(self) -> CapabilityReport:
        """Report this MCP transport's static capabilities.

        MCP is fundamentally a tool surface, so ``supports_tools`` is always
        ``True``. Discovered tool names are surfaced when ``tools/list`` has run
        (via :attr:`discovered_tools`); the server-session mode is always
        advertised because the server may hand us an ``Mcp-Session-Id``.
        """
        report_kwargs: dict[str, Any] = {
            "kind": self.kind,
            "supports_tools": True,
            "session_modes": ("stateless", _SERVER_SESSION_MODE),
            "auth_scheme": _auth_scheme_name(self._auth),
            "endpoint": self._endpoint,
        }
        # CapabilityReport may grow a discovered-tools field; populate it when
        # present without hard-coupling to a field that older cores lack.
        if "tools" in getattr(CapabilityReport, "__dataclass_fields__", {}):
            report_kwargs["tools"] = self._tool_names
        return CapabilityReport(**report_kwargs)

    async def aclose(self) -> None:
        """Release transport resources, cascading to the auth provider.

        Closes the owned data-plane :class:`httpx.AsyncClient` (if this transport
        built it) and then awaits :meth:`AuthProvider.aclose` so any token-fetch
        client the provider holds (MCP OAuth's separate discovery / token client)
        cannot leak. The auth ``aclose`` runs in the ``finally`` so a
        data-plane-close error does not suppress provider cleanup.
        """
        try:
            if self._owns_client:
                await self._client.aclose()
        finally:
            await self._auth.aclose()


class _JsonRpcError(Exception):
    """Internal signal: the server returned a JSON-RPC ``error`` member.

    Carries the raw ``{code, message, data?}`` object so :meth:`send` can fold
    it into a :class:`TransportError`. A negative/standard JSON-RPC code is a
    PROTOCOL fault; servers also use this channel to refuse a call, which we
    treat as BLOCKED when the message signals a policy/permission denial.
    """

    # Substrings that hint the server *refused* (rather than malfunctioned).
    _BLOCKED_HINTS = ("forbidden", "denied", "not allowed", "blocked", "unauthorized")

    def __init__(self, error: dict[str, Any]) -> None:
        self._code = error.get("code")
        message = error.get("message")
        self._message = message if isinstance(message, str) else "mcp: JSON-RPC error"
        super().__init__(self._message)

    def to_transport_error(self) -> TransportError:
        lowered = self._message.lower()
        category = (
            TransportErrorCategory.BLOCKED
            if any(hint in lowered for hint in self._BLOCKED_HINTS)
            else _PROTOCOL_FAULT
        )
        status = self._code if isinstance(self._code, int) else None
        return TransportError(category, self._message, status_code=status)
