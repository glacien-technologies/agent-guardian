"""Tests for transport core dataclasses (Request/Response/TokenUsage/etc.)."""

from __future__ import annotations

import pytest

from agent_guardian.transports.base import (
    Message,
    Request,
    Response,
    TokenUsage,
    ToolCall,
    Transport,
)
from agent_guardian.transports.errors import TransportError, TransportErrorCategory


def test_token_usage_defaults_zero() -> None:
    usage = TokenUsage()
    assert usage.prompt_tokens == 0
    assert usage.completion_tokens == 0
    assert usage.total_tokens == 0


def test_request_defaults() -> None:
    req = Request(prompt="hi")
    assert req.prompt == "hi"
    assert req.conversation == ()
    assert req.session is None
    assert req.metadata == {}


def test_request_with_conversation() -> None:
    convo = (Message(role="user", content="a"), Message(role="assistant", content="b"))
    req = Request(prompt="next", conversation=convo, session="s1")
    assert req.conversation == convo
    assert req.session == "s1"


def test_response_ok_when_no_error() -> None:
    resp = Response(text="hello")
    assert resp.ok is True
    assert resp.error is None
    assert resp.usage.total_tokens == 0
    assert resp.tool_calls == ()


def test_response_not_ok_when_error() -> None:
    err = TransportError(TransportErrorCategory.AUTH, "nope")
    resp = Response(error=err)
    assert resp.ok is False
    assert resp.text == ""


def test_response_carries_tool_calls() -> None:
    tc = ToolCall(name="lookup", arguments={"q": "x"}, raw={"name": "lookup"})
    resp = Response(text="", tool_calls=(tc,))
    assert resp.tool_calls[0].name == "lookup"
    assert resp.tool_calls[0].arguments == {"q": "x"}


def test_response_redacted_scrubs_text() -> None:
    resp = Response(text="here is your key sk-ant-abcdefghijklmno and more")
    red = resp.redacted()
    assert "sk-ant-abcdefghijklmno" not in red.text
    assert "REDACTED" in red.text
    # original untouched (frozen → new object)
    assert "sk-ant-abcdefghijklmno" in resp.text


def test_response_redacted_scrubs_error_and_drops_raw() -> None:
    err = TransportError(
        TransportErrorCategory.AUTH,
        "auth failed for sk-abcdefghijklmno",
        status_code=401,
    )
    resp = Response(error=err, raw={"secret": "x"})
    red = resp.redacted()
    assert red.error is not None
    assert "sk-abcdefghijklmno" not in red.error.message
    assert red.error.status_code == 401
    assert red.raw is None


def test_dataclasses_are_frozen() -> None:
    resp = Response(text="x")
    with pytest.raises((AttributeError, TypeError)):
        resp.text = "y"  # type: ignore[misc]


async def test_transport_is_abstract() -> None:
    with pytest.raises(TypeError):
        Transport()  # type: ignore[abstract]


async def test_transport_default_aclose_and_context_manager() -> None:
    class _T(Transport):
        async def send(self, request: Request) -> Response:
            return Response(text=request.prompt)

    async with _T() as t:
        resp = await t.send(Request(prompt="echo"))
        assert resp.text == "echo"
