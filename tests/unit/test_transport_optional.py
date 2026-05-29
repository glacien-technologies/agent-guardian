"""Tests for the optional networked transports (Stage 4).

The three transports — :class:`WebSocketTransport`, :class:`GrpcTransport`,
:class:`BrowserTransport` — depend on heavy third-party packages
(``websockets`` / ``grpcio`` / ``playwright``) that are **not** installed in the
test venv. So the primary contract under test is the *import guard*: each
constructor must raise a clear :class:`ImportError` naming its remediation extra
when the dependency is absent.

To exercise the happy paths we inject fake modules into :data:`sys.modules`
before construction so the lazy import resolves to a stub we drive ourselves.
This covers the send/receive/parse logic without the real packages.
"""

from __future__ import annotations

import asyncio
import builtins
import json
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from agent_guardian.transports.base import Request
from agent_guardian.transports.browser import BrowserTransport
from agent_guardian.transports.errors import TransportErrorCategory
from agent_guardian.transports.grpc_transport import GrpcTransport
from agent_guardian.transports.websocket import WebSocketTransport

# ---------------------------------------------------------------------------
# Import-guard helpers
# ---------------------------------------------------------------------------


def _block_import(monkeypatch: pytest.MonkeyPatch, *prefixes: str) -> None:
    """Make ``import <prefix>...`` raise ``ImportError`` for the given roots.

    Patches :func:`builtins.__import__` so any import whose top-level name is in
    ``prefixes`` fails as if the package were not installed, and also drops any
    already-imported submodules from :data:`sys.modules` so the lazy import in
    the transport actually re-runs ``__import__``.
    """
    for name in list(sys.modules):
        if any(name == p or name.startswith(p + ".") for p in prefixes):
            monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        root = name.split(".", 1)[0]
        if root in prefixes:
            raise ImportError(f"No module named {root!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


# ===========================================================================
# WebSocket transport
# ===========================================================================


class _FakeWsConnection:
    """A fake ``websockets`` connection: queued recv frames, recorded sends."""

    def __init__(self, frames: list[str | bytes]) -> None:
        self._frames = list(frames)
        self.sent: list[str] = []
        self.closed = False

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    async def recv(self) -> str | bytes:
        if not self._frames:
            raise _FAKE_WS_CLOSED("no more frames")
        return self._frames.pop(0)

    async def close(self) -> None:
        self.closed = True


class _FAKE_WS_CLOSED(Exception):
    """Stand-in for ``websockets.exceptions.ConnectionClosed``."""


def _install_fake_websockets(
    monkeypatch: pytest.MonkeyPatch, connection: _FakeWsConnection
) -> dict[str, Any]:
    """Inject a fake ``websockets`` module whose ``connect`` yields ``connection``."""
    captured: dict[str, Any] = {}

    async def connect(url: str, **kwargs: Any) -> _FakeWsConnection:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return connection

    module = ModuleType("websockets")
    module.connect = connect  # type: ignore[attr-defined]
    exceptions = ModuleType("websockets.exceptions")
    exceptions.ConnectionClosed = _FAKE_WS_CLOSED  # type: ignore[attr-defined]
    module.exceptions = exceptions  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "websockets", module)
    monkeypatch.setitem(sys.modules, "websockets.exceptions", exceptions)
    return captured


def test_websocket_construction_raises_without_dep(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_import(monkeypatch, "websockets")
    with pytest.raises(ImportError) as excinfo:
        WebSocketTransport(url="wss://example.com/chat")
    assert "agent-guardian[ws]" in str(excinfo.value)
    assert "websockets" in str(excinfo.value)


def test_websocket_rejects_empty_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_websockets(monkeypatch, _FakeWsConnection([]))
    with pytest.raises(ValueError, match="non-empty url"):
        WebSocketTransport(url="")


def test_websocket_rejects_non_ws_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_websockets(monkeypatch, _FakeWsConnection([]))
    with pytest.raises(ValueError, match="ws:// or wss://"):
        WebSocketTransport(url="https://example.com/chat")


def test_websocket_send_single_frame_json(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeWsConnection([json.dumps({"output": {"text": "hi there"}})])
    captured = _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(url="wss://example.com/chat", base_headers={"x-test": "1"})

    resp = asyncio.run(ws.send(Request(prompt="hello")))

    assert resp.ok
    assert resp.text == "hi there"
    # The rendered template was sent as the request frame.
    assert json.loads(conn.sent[0]) == {"input": "hello"}
    # Auth/base headers were applied at connect time.
    assert captured["kwargs"]["additional_headers"] == {"x-test": "1"}
    # Ephemeral mode closes the connection after the turn.
    assert conn.closed is True


def test_websocket_send_plain_text_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeWsConnection(["just plain text reply"])
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(url="wss://example.com/chat")

    resp = asyncio.run(ws.send(Request(prompt="hello")))

    assert resp.ok
    assert resp.text == "just plain text reply"


def test_websocket_send_bytes_frame_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeWsConnection([json.dumps({"output": {"text": "bytes-ok"}}).encode("utf-8")])
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(url="wss://example.com/chat")

    resp = asyncio.run(ws.send(Request(prompt="hello")))

    assert resp.ok
    assert resp.text == "bytes-ok"


def test_websocket_output_path_missing_is_parse_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeWsConnection([json.dumps({"wrong": "shape"})])
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(url="wss://example.com/chat", output_path="$.output.text")

    resp = asyncio.run(ws.send(Request(prompt="hello")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE


def test_websocket_streamed_frames_accumulate(monkeypatch: pytest.MonkeyPatch) -> None:
    frames = [
        json.dumps({"delta": "Hel"}),
        json.dumps({"delta": "lo "}),
        json.dumps({"delta": "world"}),
        "[DONE]",
    ]
    conn = _FakeWsConnection(frames)
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(
        url="wss://example.com/chat",
        delta_path="$.delta",
        done_signal="[DONE]",
    )

    resp = asyncio.run(ws.send(Request(prompt="hi")))

    assert resp.ok
    assert resp.text == "Hello world"


def test_websocket_streamed_frames_stop_on_close(monkeypatch: pytest.MonkeyPatch) -> None:
    # No done_signal — accumulation stops when the socket closes (recv raises).
    frames = [json.dumps({"delta": "a"}), json.dumps({"delta": "b"})]
    conn = _FakeWsConnection(frames)
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(url="wss://example.com/chat", delta_path="$.delta")

    resp = asyncio.run(ws.send(Request(prompt="hi")))

    assert resp.ok
    assert resp.text == "ab"


def test_websocket_streamed_frames_honour_max_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    frames = [json.dumps({"delta": str(i)}) for i in range(10)]
    conn = _FakeWsConnection(frames)
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(url="wss://example.com/chat", delta_path="$.delta", max_messages=3)

    resp = asyncio.run(ws.send(Request(prompt="hi")))

    assert resp.ok
    assert resp.text == "012"


def test_websocket_skips_malformed_stream_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    frames = [
        json.dumps({"delta": "ok"}),
        "{not json",
        json.dumps(["a", "list"]),  # non-dict JSON is ignored
        json.dumps({"delta": "!"}),
        "[DONE]",
    ]
    conn = _FakeWsConnection(frames)
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(
        url="wss://example.com/chat", delta_path="$.delta", done_signal="[DONE]"
    )

    resp = asyncio.run(ws.send(Request(prompt="hi")))

    assert resp.ok
    assert resp.text == "ok!"


def test_websocket_connect_failure_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing_connect(url: str, **kwargs: Any) -> Any:
        raise OSError("connection refused")

    module = ModuleType("websockets")
    module.connect = failing_connect  # type: ignore[attr-defined]
    exceptions = ModuleType("websockets.exceptions")
    exceptions.ConnectionClosed = _FAKE_WS_CLOSED  # type: ignore[attr-defined]
    module.exceptions = exceptions  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "websockets", module)
    monkeypatch.setitem(sys.modules, "websockets.exceptions", exceptions)

    ws = WebSocketTransport(url="wss://example.com/chat")
    resp = asyncio.run(ws.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE


def test_websocket_connect_falls_back_to_extra_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeWsConnection([json.dumps({"output": {"text": "ok"}})])
    seen: dict[str, Any] = {}

    async def connect(url: str, **kwargs: Any) -> _FakeWsConnection:
        if "additional_headers" in kwargs:
            raise TypeError("unexpected keyword 'additional_headers'")
        seen.update(kwargs)
        return conn

    module = ModuleType("websockets")
    module.connect = connect  # type: ignore[attr-defined]
    exceptions = ModuleType("websockets.exceptions")
    exceptions.ConnectionClosed = _FAKE_WS_CLOSED  # type: ignore[attr-defined]
    module.exceptions = exceptions  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "websockets", module)
    monkeypatch.setitem(sys.modules, "websockets.exceptions", exceptions)

    ws = WebSocketTransport(url="wss://example.com/chat", base_headers={"a": "b"})
    resp = asyncio.run(ws.send(Request(prompt="hi")))

    assert resp.ok
    assert seen["extra_headers"] == {"a": "b"}


def test_websocket_persistent_session_reuses_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeWsConnection(
        [
            json.dumps({"output": {"text": "first"}}),
            json.dumps({"output": {"text": "second"}}),
        ]
    )
    connect_calls = {"n": 0}

    async def connect(url: str, **kwargs: Any) -> _FakeWsConnection:
        connect_calls["n"] += 1
        return conn

    module = ModuleType("websockets")
    module.connect = connect  # type: ignore[attr-defined]
    exceptions = ModuleType("websockets.exceptions")
    exceptions.ConnectionClosed = _FAKE_WS_CLOSED  # type: ignore[attr-defined]
    module.exceptions = exceptions  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "websockets", module)
    monkeypatch.setitem(sys.modules, "websockets.exceptions", exceptions)

    async def run() -> tuple[str, str]:
        ws = WebSocketTransport(url="wss://example.com/chat")
        await ws.open_session()
        r1 = await ws.send(Request(prompt="a"))
        r2 = await ws.send(Request(prompt="b"))
        await ws.aclose()
        return r1.text, r2.text

    first, second = asyncio.run(run())
    assert (first, second) == ("first", "second")
    # Only one connection was opened and reused across both sends.
    assert connect_calls["n"] == 1
    assert conn.closed is True


def test_websocket_describe(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_websockets(monkeypatch, _FakeWsConnection([]))
    ws = WebSocketTransport(url="wss://example.com/chat", delta_path="$.delta")
    report = ws.describe()
    assert report.kind == "websocket"
    assert report.streaming is True
    assert report.endpoint == "wss://example.com/chat"
    assert "client_history" in report.session_modes


def test_websocket_bad_template_is_permanent(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_websockets(monkeypatch, _FakeWsConnection([]))
    ws = WebSocketTransport(url="wss://example.com/chat", send_template="{not valid json")
    resp = asyncio.run(ws.send(Request(prompt="hi")))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PERMANENT


def test_websocket_connection_closed_on_send_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ClosingConn(_FakeWsConnection):
        async def send(self, payload: str) -> None:
            raise _FAKE_WS_CLOSED("closed before send")

    _install_fake_websockets(monkeypatch, _ClosingConn([]))
    ws = WebSocketTransport(url="wss://example.com/chat")
    resp = asyncio.run(ws.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE


def test_websocket_safe_close_swallows_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BadCloseConn(_FakeWsConnection):
        async def close(self) -> None:
            raise OSError("close exploded")

    conn = _BadCloseConn([json.dumps({"output": {"text": "ok"}})])
    _install_fake_websockets(monkeypatch, conn)
    ws = WebSocketTransport(url="wss://example.com/chat")

    # Close-time failure must not surface — the reply is still returned cleanly.
    resp = asyncio.run(ws.send(Request(prompt="hi")))
    assert resp.ok
    assert resp.text == "ok"


# ===========================================================================
# gRPC transport
# ===========================================================================


class _FakeAioRpcError(Exception):
    """Stand-in for ``grpc.aio.AioRpcError``."""

    def __init__(self, code: Any, details: str) -> None:
        super().__init__(details)
        self._code = code
        self._details = details

    def code(self) -> Any:
        return self._code

    def details(self) -> str:
        return self._details


class _FakeRpcError(Exception):
    """Stand-in for the broader ``grpc.RpcError`` base."""


class _FakeStatusCode:
    """Stand-in for ``grpc.StatusCode`` members (identity-comparable)."""

    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    UNAVAILABLE = "UNAVAILABLE"
    ABORTED = "ABORTED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"


class _FakeChannel:
    """A fake gRPC channel returning a configurable unary-unary callable."""

    def __init__(self, reply: bytes | Exception) -> None:
        self._reply = reply
        self.closed = False
        self.last_payload: bytes | None = None
        self.last_metadata: Any = None

    def unary_unary(
        self, method: str, *, request_serializer: Any, response_deserializer: Any
    ) -> Any:
        async def _call(
            payload: bytes, *, metadata: Any = None, timeout: float | None = None
        ) -> bytes:
            self.last_payload = payload
            self.last_metadata = metadata
            if isinstance(self._reply, Exception):
                raise self._reply
            return self._reply

        return _call

    async def close(self) -> None:
        self.closed = True


def _install_fake_grpc(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Inject a minimal fake ``grpc`` module sufficient for construction + calls."""
    grpc_mod = ModuleType("grpc")
    grpc_mod.StatusCode = _FakeStatusCode  # type: ignore[attr-defined]
    grpc_mod.RpcError = _FakeRpcError  # type: ignore[attr-defined]
    grpc_mod.ssl_channel_credentials = lambda: "fake-creds"  # type: ignore[attr-defined]

    aio = SimpleNamespace(
        AioRpcError=_FakeAioRpcError,
        secure_channel=lambda target, creds: _FakeChannel(b""),
        insecure_channel=lambda target: _FakeChannel(b""),
    )
    grpc_mod.aio = aio  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "grpc", grpc_mod)
    return grpc_mod


def test_grpc_construction_raises_without_dep(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_import(monkeypatch, "grpc")
    with pytest.raises(ImportError) as excinfo:
        GrpcTransport(target="localhost:50051", service_method="/pkg.Svc/Method")
    assert "agent-guardian[grpc]" in str(excinfo.value)
    assert "grpcio" in str(excinfo.value)


def test_grpc_rejects_empty_target(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    with pytest.raises(ValueError, match="non-empty target"):
        GrpcTransport(target="", service_method="/pkg.Svc/Method")


def test_grpc_rejects_bad_service_method(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    with pytest.raises(ValueError, match="fully-qualified method path"):
        GrpcTransport(target="localhost:50051", service_method="pkg.Svc.Method")


def test_grpc_send_json_roundtrip_with_output_field(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    reply = json.dumps({"result": {"answer": "42"}}).encode("utf-8")
    channel = _FakeChannel(reply)
    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Ask",
        output_field="$.result.answer",
        channel=channel,
    )

    resp = asyncio.run(grpc.send(Request(prompt="what is the answer")))

    assert resp.ok
    assert resp.text == "42"
    # The rendered JSON template was sent as the request bytes.
    assert json.loads(channel.last_payload or b"{}") == {"input": "what is the answer"}


def test_grpc_send_bytes_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(b"raw reply bytes")
    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Echo",
        request_encoding="bytes",
        channel=channel,
    )

    resp = asyncio.run(grpc.send(Request(prompt="ping")))

    assert resp.ok
    assert resp.text == "raw reply bytes"
    assert channel.last_payload == b"ping"


def test_grpc_metadata_includes_base_and_per_request(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(b"ok")
    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Echo",
        request_encoding="bytes",
        metadata={"X-Base": "base"},
        channel=channel,
    )

    resp = asyncio.run(
        grpc.send(Request(prompt="hi", metadata={"grpc_metadata": {"X-Extra": "extra"}}))
    )

    assert resp.ok
    meta = dict(channel.last_metadata)
    # Keys are lower-cased per gRPC metadata convention.
    assert meta["x-base"] == "base"
    assert meta["x-extra"] == "extra"


def test_grpc_output_field_missing_is_parse_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(json.dumps({"nope": 1}).encode("utf-8"))
    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Ask",
        output_field="$.result.answer",
        channel=channel,
    )

    resp = asyncio.run(grpc.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE


def test_grpc_non_json_reply_with_output_field_is_parse_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(b"not json at all")
    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Ask",
        output_field="$.x",
        channel=channel,
    )

    resp = asyncio.run(grpc.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE


@pytest.mark.parametrize(
    ("code", "category"),
    [
        (_FakeStatusCode.UNAUTHENTICATED, TransportErrorCategory.AUTH),
        (_FakeStatusCode.PERMISSION_DENIED, TransportErrorCategory.AUTH),
        (_FakeStatusCode.RESOURCE_EXHAUSTED, TransportErrorCategory.RATE_LIMIT),
        (_FakeStatusCode.DEADLINE_EXCEEDED, TransportErrorCategory.TIMEOUT),
        (_FakeStatusCode.UNAVAILABLE, TransportErrorCategory.UNREACHABLE),
        (_FakeStatusCode.ABORTED, TransportErrorCategory.UNREACHABLE),
        (_FakeStatusCode.INVALID_ARGUMENT, TransportErrorCategory.PERMANENT),
    ],
)
def test_grpc_status_code_mapping(
    monkeypatch: pytest.MonkeyPatch, code: str, category: TransportErrorCategory
) -> None:
    _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(_FakeAioRpcError(code, f"detail for {code}"))
    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Echo",
        request_encoding="bytes",
        channel=channel,
    )

    resp = asyncio.run(grpc.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is category


def test_grpc_builds_insecure_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    grpc_mod = _install_fake_grpc(monkeypatch)
    built: dict[str, Any] = {}

    def insecure(target: str) -> _FakeChannel:
        built["target"] = target
        return _FakeChannel(b"plain")

    grpc_mod.aio.insecure_channel = insecure  # type: ignore[attr-defined]

    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Echo",
        request_encoding="bytes",
        use_tls=False,
    )
    resp = asyncio.run(grpc.send(Request(prompt="hi")))

    assert resp.ok
    assert resp.text == "plain"
    assert built["target"] == "localhost:50051"


def test_grpc_builds_secure_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    grpc_mod = _install_fake_grpc(monkeypatch)
    built: dict[str, Any] = {}

    def secure(target: str, creds: Any) -> _FakeChannel:
        built["target"] = target
        built["creds"] = creds
        return _FakeChannel(b"secure")

    grpc_mod.aio.secure_channel = secure  # type: ignore[attr-defined]

    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Echo",
        request_encoding="bytes",
        use_tls=True,
    )
    resp = asyncio.run(grpc.send(Request(prompt="hi")))

    assert resp.ok
    assert resp.text == "secure"
    assert built["creds"] == "fake-creds"


def test_grpc_aclose_closes_owned_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    grpc_mod = _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(b"ok")
    grpc_mod.aio.insecure_channel = lambda target: channel  # type: ignore[attr-defined]

    async def run() -> bool:
        grpc = GrpcTransport(
            target="localhost:50051",
            service_method="/pkg.Svc/Echo",
            request_encoding="bytes",
            use_tls=False,
        )
        await grpc.send(Request(prompt="hi"))
        await grpc.aclose()
        return channel.closed

    assert asyncio.run(run()) is True


def test_grpc_injected_channel_not_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(b"ok")

    async def run() -> bool:
        grpc = GrpcTransport(
            target="localhost:50051",
            service_method="/pkg.Svc/Echo",
            request_encoding="bytes",
            channel=channel,
        )
        await grpc.send(Request(prompt="hi"))
        await grpc.aclose()
        return channel.closed

    # An injected channel is not owned, so aclose must not close it.
    assert asyncio.run(run()) is False


def test_grpc_describe(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    grpc = GrpcTransport(target="localhost:50051", service_method="/pkg.Svc/Echo")
    report = grpc.describe()
    assert report.kind == "grpc"
    assert report.streaming is False
    assert report.supports_tools is False
    assert report.endpoint == "localhost:50051"


def test_grpc_bad_template_is_permanent(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_grpc(monkeypatch)
    channel = _FakeChannel(b"unused")
    grpc = GrpcTransport(
        target="localhost:50051",
        service_method="/pkg.Svc/Echo",
        send_template="{not valid json",
        channel=channel,
    )
    resp = asyncio.run(grpc.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PERMANENT
    # A bad template never reaches the channel.
    assert channel.last_payload is None


# ===========================================================================
# Browser transport
# ===========================================================================


class _FakePage:
    """A fake Playwright page recording the navigate→fill→submit→read flow."""

    def __init__(self, output_text: str | None, *, fail_on: str | None = None) -> None:
        self._output_text = output_text
        self._fail_on = fail_on
        self.actions: list[str] = []
        self.default_timeout: int | None = None
        self.default_nav_timeout: int | None = None

    def set_default_timeout(self, ms: int) -> None:
        self.default_timeout = ms

    def set_default_navigation_timeout(self, ms: int) -> None:
        self.default_nav_timeout = ms

    def _maybe_fail(self, action: str) -> None:
        if self._fail_on == action:
            if action == "goto":
                raise _FakePlaywrightTimeoutError("nav timed out")
            raise _FakePlaywrightError(f"failed at {action}")

    async def goto(self, url: str, *, timeout: int | None = None) -> None:
        self.actions.append(f"goto:{url}")
        self._maybe_fail("goto")

    async def fill(self, selector: str, value: str, *, timeout: int | None = None) -> None:
        self.actions.append(f"fill:{selector}={value}")
        self._maybe_fail("fill")

    async def click(self, selector: str, *, timeout: int | None = None) -> None:
        self.actions.append(f"click:{selector}")
        self._maybe_fail("click")

    async def press(self, selector: str, key: str, *, timeout: int | None = None) -> None:
        self.actions.append(f"press:{selector}:{key}")
        self._maybe_fail("press")

    async def wait_for_selector(self, selector: str, *, timeout: int | None = None) -> None:
        self.actions.append(f"wait:{selector}")
        self._maybe_fail("wait")

    async def text_content(self, selector: str, *, timeout: int | None = None) -> str | None:
        self.actions.append(f"read:{selector}")
        self._maybe_fail("read")
        return self._output_text


class _FakeBrowser:
    def __init__(self, page: _FakePage) -> None:
        self._page = page
        self.closed = False

    async def new_page(self) -> _FakePage:
        return self._page

    async def close(self) -> None:
        self.closed = True


class _FakeBrowserType:
    def __init__(self, browser: _FakeBrowser) -> None:
        self._browser = browser
        self.launch_kwargs: dict[str, Any] = {}

    async def launch(self, **kwargs: Any) -> _FakeBrowser:
        self.launch_kwargs = kwargs
        return self._browser


class _FakePlaywright:
    def __init__(self, browser_type: _FakeBrowserType) -> None:
        self.chromium = browser_type
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


class _FakeAsyncPlaywrightCM:
    """Mimics ``async_playwright()`` — has a ``.start()`` coroutine."""

    def __init__(self, playwright: _FakePlaywright) -> None:
        self._playwright = playwright

    async def start(self) -> _FakePlaywright:
        return self._playwright


class _FakePlaywrightError(Exception):
    """Stand-in for ``playwright.async_api.Error``."""


class _FakePlaywrightTimeoutError(_FakePlaywrightError):
    """Stand-in for ``playwright.async_api.TimeoutError``."""


def _install_fake_playwright(monkeypatch: pytest.MonkeyPatch, page: _FakePage) -> dict[str, Any]:
    """Inject a fake ``playwright.async_api`` module driving ``page``."""
    browser = _FakeBrowser(page)
    browser_type = _FakeBrowserType(browser)
    playwright = _FakePlaywright(browser_type)

    def async_playwright() -> _FakeAsyncPlaywrightCM:
        return _FakeAsyncPlaywrightCM(playwright)

    pkg = ModuleType("playwright")
    async_api = ModuleType("playwright.async_api")
    async_api.async_playwright = async_playwright  # type: ignore[attr-defined]
    async_api.Error = _FakePlaywrightError  # type: ignore[attr-defined]
    async_api.TimeoutError = _FakePlaywrightTimeoutError  # type: ignore[attr-defined]
    pkg.async_api = async_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)
    return {"browser": browser, "browser_type": browser_type, "playwright": playwright}


def test_browser_construction_raises_without_dep(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_import(monkeypatch, "playwright")
    with pytest.raises(ImportError) as excinfo:
        BrowserTransport(
            url="https://chat.example.com",
            input_selector="#prompt",
            output_selector="#reply",
            submit_selector="#send",
        )
    assert "agent-guardian[browser]" in str(excinfo.value)
    assert "playwright" in str(excinfo.value)


def test_browser_rejects_missing_selectors(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(monkeypatch, _FakePage("x"))
    with pytest.raises(ValueError, match="non-empty url"):
        BrowserTransport(url="", input_selector="#p", output_selector="#r", submit_selector="#s")
    with pytest.raises(ValueError, match="input_selector"):
        BrowserTransport(
            url="https://x", input_selector="", output_selector="#r", submit_selector="#s"
        )
    with pytest.raises(ValueError, match="output_selector"):
        BrowserTransport(
            url="https://x", input_selector="#p", output_selector="", submit_selector="#s"
        )
    with pytest.raises(ValueError, match="submit_selector or submit_with_enter"):
        BrowserTransport(url="https://x", input_selector="#p", output_selector="#r")


def test_browser_send_click_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage("the assistant reply")
    handles = _install_fake_playwright(monkeypatch, page)
    bt = BrowserTransport(
        url="https://chat.example.com",
        input_selector="#prompt",
        output_selector="#reply",
        submit_selector="#send",
    )

    resp = asyncio.run(bt.send(Request(prompt="attack payload")))

    assert resp.ok
    assert resp.text == "the assistant reply"
    assert "goto:https://chat.example.com" in page.actions
    assert "fill:#prompt=attack payload" in page.actions
    assert "click:#send" in page.actions
    assert "read:#reply" in page.actions
    # Ephemeral mode tears the browser down.
    assert handles["browser"].closed is True
    assert handles["playwright"].stopped is True
    assert handles["browser_type"].launch_kwargs == {"headless": True}


def test_browser_send_enter_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage("enter reply")
    _install_fake_playwright(monkeypatch, page)
    bt = BrowserTransport(
        url="https://chat.example.com",
        input_selector="#prompt",
        output_selector="#reply",
        submit_with_enter=True,
    )

    resp = asyncio.run(bt.send(Request(prompt="hello")))

    assert resp.ok
    assert resp.text == "enter reply"
    assert "press:#prompt:Enter" in page.actions
    assert not any(a.startswith("click:") for a in page.actions)


def test_browser_missing_output_text_is_parse_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage(None)
    _install_fake_playwright(monkeypatch, page)
    bt = BrowserTransport(
        url="https://chat.example.com",
        input_selector="#prompt",
        output_selector="#reply",
        submit_selector="#send",
    )

    resp = asyncio.run(bt.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE


def test_browser_navigation_timeout_is_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage("x", fail_on="goto")
    _install_fake_playwright(monkeypatch, page)
    bt = BrowserTransport(
        url="https://chat.example.com",
        input_selector="#prompt",
        output_selector="#reply",
        submit_selector="#send",
    )

    resp = asyncio.run(bt.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.TIMEOUT


def test_browser_selector_failure_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage("x", fail_on="fill")
    _install_fake_playwright(monkeypatch, page)
    bt = BrowserTransport(
        url="https://chat.example.com",
        input_selector="#prompt",
        output_selector="#reply",
        submit_selector="#send",
    )

    resp = asyncio.run(bt.send(Request(prompt="hi")))

    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE


def test_browser_persistent_session_reuses_page(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage("reply")
    handles = _install_fake_playwright(monkeypatch, page)

    async def run() -> tuple[str, str, bool]:
        bt = BrowserTransport(
            url="https://chat.example.com",
            input_selector="#prompt",
            output_selector="#reply",
            submit_selector="#send",
        )
        await bt.open_session()
        r1 = await bt.send(Request(prompt="a"))
        # Browser should still be open between sends.
        open_between = not handles["browser"].closed
        r2 = await bt.send(Request(prompt="b"))
        await bt.aclose()
        return r1.text, r2.text, open_between

    first, second, open_between = asyncio.run(run())
    assert first == "reply"
    assert second == "reply"
    assert open_between is True
    assert handles["browser"].closed is True


def test_browser_custom_browser_name_and_headful(monkeypatch: pytest.MonkeyPatch) -> None:
    page = _FakePage("ok")
    browser = _FakeBrowser(page)
    browser_type = _FakeBrowserType(browser)
    playwright = _FakePlaywright(browser_type)
    # Expose under a non-default attribute name (firefox).
    playwright.firefox = browser_type  # type: ignore[attr-defined]

    def async_playwright() -> _FakeAsyncPlaywrightCM:
        return _FakeAsyncPlaywrightCM(playwright)

    pkg = ModuleType("playwright")
    async_api = ModuleType("playwright.async_api")
    async_api.async_playwright = async_playwright  # type: ignore[attr-defined]
    async_api.Error = _FakePlaywrightError  # type: ignore[attr-defined]
    async_api.TimeoutError = _FakePlaywrightTimeoutError  # type: ignore[attr-defined]
    pkg.async_api = async_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)

    bt = BrowserTransport(
        url="https://chat.example.com",
        input_selector="#prompt",
        output_selector="#reply",
        submit_selector="#send",
        headless=False,
        browser_name="firefox",
    )
    resp = asyncio.run(bt.send(Request(prompt="hi")))

    assert resp.ok
    assert browser_type.launch_kwargs == {"headless": False}


def test_browser_describe(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_playwright(monkeypatch, _FakePage("x"))
    bt = BrowserTransport(
        url="https://chat.example.com",
        input_selector="#prompt",
        output_selector="#reply",
        submit_selector="#send",
    )
    report = bt.describe()
    assert report.kind == "browser"
    assert report.streaming is False
    assert report.supports_tools is False
    assert report.auth_scheme is None
    assert report.endpoint == "https://chat.example.com"
