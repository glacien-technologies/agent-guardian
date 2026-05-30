"""WebSocket transport (Stage 4, optional) — a turn over a ``ws(s)://`` socket.

A :class:`WebSocketTransport` speaks one request/one reply over a WebSocket
connection using the third-party ``websockets`` library. Like every other
transport it is built from **primitives** (a url, a Jinja send-template, an
``output_path`` JSONPath, an auth provider) — never from a Contract; the
contract→transport wiring is the factory's job, preserving the package's
decoupling rule.

The send shape mirrors :class:`agent_guardian.transports.http.HttpTransport`:
the request body is rendered by
:func:`agent_guardian.transports.templating.render_body` and the reply is parsed
with the project's dotted-JSONPath walker
:func:`agent_guardian.adapters.http_shapes.generic_shape.walk_jsonpath`. Many
WebSocket agents stream their reply as a sequence of JSON frames terminated by a
final/done frame; we reuse the streaming-accumulation logic from
:mod:`agent_guardian.transports.streaming` to fold those frames into one text
when a ``delta_path`` is configured, otherwise the first JSON frame is parsed
directly via ``output_path``.

``websockets`` is an OPTIONAL dependency. It is imported lazily and, when
absent, construction raises a clear :class:`ImportError` naming the
``agent-guardian[ws]`` extra so the operator knows the remediation.

:meth:`send` never raises for a transport fault — it catches connection /
protocol / timeout faults and returns a :class:`Response` whose ``error`` is the
mapped :class:`TransportError`.

Two session modes are supported:

* ``stateless`` — a fresh connection is opened and closed for every
  :meth:`send` (the default).
* ``client_history`` — the prior conversation is replayed inside the rendered
  template (the ``conversation`` template variable), again over a fresh
  connection per turn; the transport holds no server-side socket state.

A persistent-socket mode (open on :meth:`open_session`, reuse across turns) is
available by calling :meth:`open_session` first: subsequent sends reuse the open
connection until :meth:`close_session` / :meth:`aclose`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath
from agent_guardian.llm.errors import (
    LLMError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    Transport,
)
from agent_guardian.transports.errors import map_llm_error
from agent_guardian.transports.streaming import StreamResult
from agent_guardian.transports.templating import render_body

if TYPE_CHECKING:  # pragma: no cover - typing-only import, never executed
    from collections.abc import AsyncIterator

__all__ = ["WebSocketTransport"]

_LOG = logging.getLogger(__name__)

_DEFAULT_TEMPLATE = '{"input": "{{ prompt }}"}'

# Remediation surfaced when the optional ``websockets`` dependency is absent.
_MISSING_DEP_MSG = (
    "WebSocketTransport requires the 'websockets' package, which is not installed. "
    "Install it with: pip install 'agent-guardian[ws]'"
)

SessionMode = Literal["stateless", "client_history"]


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


def _load_websockets() -> Any:
    """Import and return the ``websockets`` module, or raise a clear error.

    The dependency is optional (extra ``ws``); we import it lazily so the base
    install never pays the cost and so an operator who never scans a WebSocket
    target is unaffected. When absent we raise an :class:`ImportError` whose
    message names the remediation extra.
    """
    try:
        import websockets
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        _LOG.debug("websocket transport: 'websockets' import failed (%s)", exc)
        raise ImportError(_MISSING_DEP_MSG) from exc
    return websockets


class WebSocketTransport(Transport):
    """One-turn-per-send transport over a ``ws(s)://`` WebSocket endpoint."""

    kind: ClassVar[str] = "websocket"

    def __init__(
        self,
        *,
        url: str,
        send_template: str = _DEFAULT_TEMPLATE,
        output_path: str = "$.output.text",
        delta_path: str | None = None,
        done_signal: str | None = None,
        session_mode: SessionMode = "stateless",
        auth: AuthProvider | None = None,
        base_headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_messages: int = 256,
    ) -> None:
        if not url:
            raise ValueError("WebSocketTransport requires a non-empty url")
        if not url.startswith(("ws://", "wss://")):
            raise ValueError(f"WebSocketTransport url must be ws:// or wss:// (got {url!r})")
        # Fail fast at construction when the optional dependency is missing so
        # the operator gets the remediation immediately, not on first send.
        self._websockets = _load_websockets()

        self._url = url
        self._send_template = send_template
        self._output_path = output_path
        self._delta_path = delta_path
        self._done_signal = done_signal
        self._session_mode: SessionMode = session_mode
        self._auth: AuthProvider = auth or NoAuth()
        self._base_headers = dict(base_headers or {})
        self._timeout_seconds = timeout_seconds
        self._max_messages = max_messages

        # Persistent connection when a session has been opened; ``None`` in the
        # per-send (default) mode. Typed ``Any`` because the concrete
        # connection class lives in the optional ``websockets`` package.
        self._connection: Any = None
        # Serialises sends over a shared persistent connection (a WebSocket is
        # a single full-duplex stream — concurrent sends would interleave).
        self._send_lock = asyncio.Lock()

    @property
    def url(self) -> str:
        return self._url

    # ---- connection plumbing ----------------------------------------------

    async def _build_headers(self) -> dict[str, str]:
        """Compose connection headers (base headers + applied auth)."""
        headers: dict[str, str] = dict(self._base_headers)
        ctx = AuthContext(method="GET", url=self._url, headers=headers)
        await self._auth.apply(ctx)
        return ctx.headers

    async def _connect(self) -> Any:
        """Open a new WebSocket connection with auth headers applied.

        Raises :class:`LLMTransientError` / :class:`LLMTimeoutError` on a
        connection fault so the public :meth:`send` can fold it into a
        :class:`Response`.
        """
        headers = await self._build_headers()
        try:
            # ``websockets`` ≥ 12 accepts ``additional_headers``; older
            # releases used ``extra_headers``. Probe at runtime so we work
            # against either without a hard version pin.
            connect = self._websockets.connect
            try:
                return await connect(
                    self._url,
                    additional_headers=headers or None,
                    open_timeout=self._timeout_seconds,
                )
            except TypeError as exc:
                _LOG.debug(
                    "websocket transport: 'additional_headers' rejected (%s) — "
                    "retrying with 'extra_headers'",
                    exc,
                )
                return await connect(
                    self._url,
                    extra_headers=headers or None,
                    open_timeout=self._timeout_seconds,
                )
        except asyncio.TimeoutError as exc:
            raise LLMTimeoutError(f"websocket: connect timeout: {exc}") from exc
        except OSError as exc:
            raise LLMTransientError(f"websocket: connect failed: {exc}") from exc

    async def _recv_text(self, connection: Any) -> str:
        """Receive the full reply text from ``connection``.

        When a ``delta_path`` is configured we read frames until the done
        signal (or the socket closes / ``max_messages`` is hit), accumulating
        each frame's incremental delta. Otherwise we read a single frame and
        parse it directly through ``output_path``.
        """
        if self._delta_path is None:
            raw = await self._recv_one(connection)
            return self._parse_single(raw)
        return await self._accumulate_frames(connection)

    async def _recv_one(self, connection: Any) -> str:
        """Receive exactly one frame as text, honouring the per-recv timeout."""
        try:
            message = await asyncio.wait_for(connection.recv(), timeout=self._timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise LLMTimeoutError(f"websocket: recv timeout: {exc}") from exc
        return message.decode() if isinstance(message, bytes) else str(message)

    def _parse_single(self, raw: str) -> str:
        """Parse a single JSON reply frame via ``output_path``.

        If the frame is not JSON we treat the whole frame as the reply text
        (some echo/raw servers send plain text). If it is JSON but the path
        yields nothing we raise a parse fault.
        """
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            _LOG.debug("websocket transport: reply is not JSON (%s) — using raw text", exc)
            return raw
        value = walk_jsonpath(payload, self._output_path)
        if value is None:
            raise LLMResponseFormatError(
                f"websocket: output_path {self._output_path!r} produced no value"
            )
        return str(value)

    async def _accumulate_frames(self, connection: Any) -> str:
        """Read streamed JSON frames into a final text using ``delta_path``.

        Reuses :class:`agent_guardian.transports.streaming.StreamResult` for the
        accumulation contract. Each frame is parsed as a standalone JSON object;
        its ``delta_path`` delta is appended. A frame matching ``done_signal``
        (raw-string compare against the frame) terminates the stream; otherwise
        the loop ends when the socket closes or ``max_messages`` is reached.
        """
        result = StreamResult()
        count = 0
        async for raw in self._iter_frames(connection):
            count += 1
            if self._done_signal is not None and raw.strip() == self._done_signal:
                break
            self._fold_frame(result, raw)
            if count >= self._max_messages:
                _LOG.debug(
                    "websocket transport: hit max_messages=%d — stopping accumulation",
                    self._max_messages,
                )
                break
        result.done = True
        return result.text

    async def _iter_frames(self, connection: Any) -> AsyncIterator[str]:
        """Yield reply frames as text until the socket closes (or times out)."""
        closed = self._websockets.exceptions.ConnectionClosed
        while True:
            try:
                message = await asyncio.wait_for(connection.recv(), timeout=self._timeout_seconds)
            except asyncio.TimeoutError as exc:
                raise LLMTimeoutError(f"websocket: recv timeout: {exc}") from exc
            except closed as exc:
                _LOG.debug("websocket transport: connection closed mid-stream (%s)", exc)
                return
            yield message.decode() if isinstance(message, bytes) else str(message)

    def _fold_frame(self, result: StreamResult, raw: str) -> None:
        """Parse one streamed frame and fold its ``delta_path`` delta into text."""
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            _LOG.debug("websocket transport: skipping malformed stream frame (%s)", exc)
            return
        if not isinstance(event, dict):
            return
        result.events.append(event)
        assert self._delta_path is not None  # guarded by caller
        delta = walk_jsonpath(event, self._delta_path)
        if isinstance(delta, str):
            result.text += delta

    # ---- Transport surface -------------------------------------------------

    async def send(self, request: Request) -> Response:
        """Send one turn over the socket. Never raises for transport faults."""
        try:
            body = self._build_body(request)
        except LLMError as exc:
            _LOG.debug("websocket transport: request body build failed (%s)", exc)
            return Response(error=map_llm_error(exc))

        payload = json.dumps(body)
        try:
            if self._connection is not None:
                text = await self._send_over(self._connection, payload, lock=True)
            else:
                text = await self._send_ephemeral(payload)
            return Response(text=text, raw=text)
        except LLMError as exc:
            _LOG.debug("websocket transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    def _build_body(self, request: Request) -> dict[str, Any]:
        """Render the send template for ``request`` (raises on a bad template)."""
        return render_body(
            self._send_template,
            prompt=request.prompt,
            session=request.session,
            conversation=request.conversation,
        )

    async def _send_ephemeral(self, payload: str) -> str:
        """Open a fresh connection, send + receive, then close it."""
        connection = await self._connect()
        try:
            return await self._send_over(connection, payload, lock=False)
        finally:
            await self._safe_close(connection)

    async def _send_over(self, connection: Any, payload: str, *, lock: bool) -> str:
        """Write ``payload`` to ``connection`` and read the reply text.

        ``lock`` serialises sends over a shared persistent connection; ephemeral
        sends own their socket exclusively and skip the lock.
        """
        if lock:
            async with self._send_lock:
                return await self._write_then_read(connection, payload)
        return await self._write_then_read(connection, payload)

    async def _write_then_read(self, connection: Any, payload: str) -> str:
        closed = self._websockets.exceptions.ConnectionClosed
        try:
            await connection.send(payload)
        except closed as exc:
            raise LLMTransientError(f"websocket: connection closed on send: {exc}") from exc
        return await self._recv_text(connection)

    async def _safe_close(self, connection: Any) -> None:
        """Close ``connection``, swallowing close-time faults."""
        try:
            await connection.close()
        except OSError as exc:
            _LOG.debug("websocket transport: error closing connection (%s)", exc)

    async def open_session(self) -> None:
        """Open a persistent connection reused by later sends until closed."""
        if self._connection is None:
            self._connection = await self._connect()

    async def close_session(self) -> None:
        """Close the persistent connection opened by :meth:`open_session`."""
        if self._connection is not None:
            await self._safe_close(self._connection)
            self._connection = None

    async def aclose(self) -> None:
        """Release transport resources, cascading to the auth provider.

        Closes any persistent WebSocket connection opened via
        :meth:`open_session` and then awaits :meth:`AuthProvider.aclose` so any
        token-fetch client the provider holds (OAuth2 / Entra) cannot leak. The
        auth ``aclose`` runs in the ``finally`` so a socket-close error does not
        suppress provider cleanup.
        """
        try:
            await self.close_session()
        finally:
            await self._auth.aclose()

    def describe(self) -> CapabilityReport:
        """Report this WebSocket transport's static capabilities.

        ``streaming`` reflects whether frame accumulation (``delta_path``) is
        configured. Tool calls are not parsed by this transport.
        """
        session_modes: tuple[str, ...] = ("stateless", "client_history")
        return CapabilityReport(
            kind=self.kind,
            streaming=self._delta_path is not None,
            supports_tools=False,
            session_modes=session_modes,
            auth_scheme=_auth_scheme_name(self._auth),
            endpoint=self._url,
        )
