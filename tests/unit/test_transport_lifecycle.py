"""Tests for the Transport lifecycle surface and HTTP outbound session-id.

Covers the Stage 2 additions:

* :class:`ProbeResult` / :class:`CapabilityReport` value objects.
* The default :meth:`Transport.probe` (benign round-trip → mapped result).
* :meth:`HttpTransport.describe` reflecting tool/stream/auth/session config.
* Outbound server-session-id placement (header / body / query).
"""

from __future__ import annotations

import httpx
import respx

from agent_guardian.transports.auth.bearer import BearerAuth
from agent_guardian.transports.base import (
    CapabilityReport,
    ProbeResult,
    Request,
    Response,
    Transport,
)
from agent_guardian.transports.errors import TransportError, TransportErrorCategory
from agent_guardian.transports.http import HttpTransport

ENDPOINT = "https://target.example.com/v1/chat"


def _make_transport(**kwargs: object) -> HttpTransport:
    base: dict[str, object] = {
        "endpoint": ENDPOINT,
        "request_template": '{"input": "{{ prompt }}"}',
        "output_path": "$.output.text",
        "max_retries": 0,
    }
    base.update(kwargs)
    return HttpTransport(**base)  # type: ignore[arg-type]


# --- value objects ----------------------------------------------------------


def test_probe_result_defaults() -> None:
    ok = ProbeResult(ok=True, detail="hello")
    assert ok.ok is True
    assert ok.detail == "hello"
    assert ok.error is None

    err = TransportError(TransportErrorCategory.UNREACHABLE, "down")
    bad = ProbeResult(ok=False, error=err)
    assert bad.ok is False
    assert bad.detail == ""
    assert bad.error is err


def test_capability_report_defaults() -> None:
    rep = CapabilityReport(kind="http")
    assert rep.kind == "http"
    assert rep.streaming is False
    assert rep.supports_tools is False
    assert rep.session_modes == ()
    assert rep.auth_scheme is None
    assert rep.endpoint is None


def test_transport_class_kind_default() -> None:
    assert Transport.kind == "transport"
    assert HttpTransport.kind == "http"


# --- default lifecycle on a minimal Transport -------------------------------


class _FakeTransport(Transport):
    """Minimal transport returning a canned response (no network)."""

    def __init__(self, response: Response) -> None:
        self._response = response

    async def send(self, request: Request) -> Response:
        return self._response


async def test_default_describe_reports_only_kind() -> None:
    t = _FakeTransport(Response(text="x"))
    rep = t.describe()
    assert rep == CapabilityReport(kind="transport")


async def test_default_probe_ok_truncates_detail() -> None:
    long_text = "A" * 500
    t = _FakeTransport(Response(text=long_text))
    result = await t.probe()
    assert result.ok is True
    assert result.detail == "A" * 200
    assert result.error is None


async def test_default_probe_failure_carries_error() -> None:
    err = TransportError(TransportErrorCategory.AUTH, "nope")
    t = _FakeTransport(Response(error=err))
    result = await t.probe()
    assert result.ok is False
    assert result.error is err


async def test_default_open_close_session_are_noops() -> None:
    t = _FakeTransport(Response(text="x"))
    assert await t.open_session() is None
    assert await t.close_session() is None
    assert await t.aclose() is None


# --- HttpTransport.probe via the default (respx) ----------------------------


@respx.mock
async def test_http_probe_ok_on_200() -> None:
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "I am a target."}})
    )
    t = _make_transport()
    result = await t.probe()
    assert result.ok is True
    assert result.detail == "I am a target."
    # The default probe sends the benign introduction prompt.
    assert b"please introduce yourself" in route.calls.last.request.content
    await t.aclose()


@respx.mock
async def test_http_probe_failure_on_500_is_unreachable() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(500, text="boom"))
    t = _make_transport()
    result = await t.probe()
    assert result.ok is False
    assert result.error is not None
    assert result.error.category is TransportErrorCategory.UNREACHABLE
    await t.aclose()


# --- HttpTransport.describe --------------------------------------------------


def test_describe_minimal() -> None:
    t = _make_transport()
    rep = t.describe()
    assert rep.kind == "http"
    assert rep.endpoint == ENDPOINT
    assert rep.streaming is False
    assert rep.supports_tools is False
    assert rep.auth_scheme is None
    assert rep.session_modes == ("stateless", "client_history")


def test_describe_reflects_tools_stream_auth_and_session() -> None:
    t = _make_transport(
        tool_call_path="$.tools",
        stream=True,
        session_path="$.sid",
        auth=BearerAuth("tok"),
    )
    rep = t.describe()
    assert rep.supports_tools is True
    assert rep.streaming is True
    assert rep.auth_scheme == "Bearer"
    assert rep.session_modes == ("stateless", "server_session", "client_history")


def test_describe_server_session_from_outbound_placement() -> None:
    t = _make_transport(session_send_in="header", session_send_name="X-Session-Id")
    rep = t.describe()
    assert "server_session" in rep.session_modes


# --- outbound session-id placement ------------------------------------------


@respx.mock
async def test_outbound_session_in_header() -> None:
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "ok"}})
    )
    t = _make_transport(session_send_in="header", session_send_name="X-Session-Id")
    resp = await t.send(Request(prompt="hi", session="S99"))
    assert resp.ok
    assert route.calls.last.request.headers["X-Session-Id"] == "S99"
    await t.aclose()


@respx.mock
async def test_outbound_session_in_body() -> None:
    import json as _json

    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "ok"}})
    )
    t = _make_transport(session_send_in="body", session_send_name="session_id")
    resp = await t.send(Request(prompt="hi", session="S77"))
    assert resp.ok
    sent = _json.loads(route.calls.last.request.content)
    assert sent["session_id"] == "S77"
    # Existing template content is preserved alongside the injected key.
    assert sent["input"] == "hi"
    await t.aclose()


@respx.mock
async def test_outbound_session_in_query() -> None:
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "ok"}})
    )
    t = _make_transport(session_send_in="query", session_send_name="sid")
    resp = await t.send(Request(prompt="hi", session="S55"))
    assert resp.ok
    assert route.calls.last.request.url.params["sid"] == "S55"
    # The transport endpoint is restored after a query-mode send.
    assert t.endpoint == ENDPOINT
    await t.aclose()


@respx.mock
async def test_outbound_session_omitted_when_session_none() -> None:
    import json as _json

    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "ok"}})
    )
    t = _make_transport(session_send_in="header", session_send_name="X-Session-Id")
    resp = await t.send(Request(prompt="hi"))  # no session
    assert resp.ok
    assert "X-Session-Id" not in route.calls.last.request.headers
    sent = _json.loads(route.calls.last.request.content)
    assert "session_id" not in sent
    await t.aclose()


def test_session_send_name_required_when_in_set() -> None:
    import pytest

    with pytest.raises(ValueError, match="session_send_name"):
        HttpTransport(endpoint=ENDPOINT, session_send_in="header")
