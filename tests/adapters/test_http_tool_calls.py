"""Tests for HttpAdapter structured tool_call extraction.

The recon agent needs to see the *actual structured tool blocks* the target
returned, not just substring-match the assistant text. These tests assert
that :attr:`HttpAdapter._last_response` carries non-empty ``tool_calls``
for each provider shape that supports them, and that an empty tool block
(or a malformed one) does not raise -- it just leaves the snapshot
``tool_calls`` empty.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from agent_guardian.adapters.http import (
    HttpAdapter,
    HttpAdapterLastResponse,
    HttpAdapterToolCall,
    _extract_tool_calls,
)


def _openai_with_tool_call(text: str = "calling...") -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {
                    "content": text,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "get_balance",
                                "arguments": json.dumps({"account_id": "12345"}),
                            },
                        },
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "search_kb",
                                "arguments": json.dumps({"q": "refund policy"}),
                            },
                        },
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "model": "gpt-4o-mini",
    }


def _anthropic_with_tool_use(text: str = "thinking") -> dict[str, Any]:
    return {
        "content": [
            {"type": "text", "text": text},
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "get_balance",
                "input": {"account_id": "12345"},
            },
        ],
        "stop_reason": "tool_use",
        "model": "claude-3-5-sonnet-latest",
    }


_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


# ----------------------------------------------------------------- extractor


def test_extract_tool_calls_openai_decodes_argument_json_string() -> None:
    calls = _extract_tool_calls(_openai_with_tool_call(), shape_name="openai")
    assert len(calls) == 2
    assert calls[0].name == "get_balance"
    assert calls[0].arguments == {"account_id": "12345"}
    assert calls[1].name == "search_kb"
    assert calls[1].arguments == {"q": "refund policy"}


def test_extract_tool_calls_anthropic_skips_text_blocks() -> None:
    calls = _extract_tool_calls(_anthropic_with_tool_use(), shape_name="anthropic")
    # The text block has no ``name`` -- the extractor must skip it, not crash.
    assert len(calls) == 1
    assert calls[0].name == "get_balance"
    assert calls[0].arguments == {"account_id": "12345"}


def test_extract_tool_calls_returns_empty_when_path_missing() -> None:
    assert (
        _extract_tool_calls({"choices": [{"message": {"content": "hi"}}]}, shape_name="openai")
        == ()
    )


def test_extract_tool_calls_returns_empty_on_unknown_shape() -> None:
    assert _extract_tool_calls({"any": "thing"}, shape_name="bogus") == ()


def test_extract_tool_calls_handles_malformed_args_string() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"function": {"name": "f", "arguments": "{not-json"}},
                    ]
                }
            }
        ]
    }
    calls = _extract_tool_calls(payload, shape_name="openai")
    # ``arguments`` couldn't be decoded -> fall back to empty dict; never raise.
    assert len(calls) == 1
    assert calls[0].name == "f"
    assert calls[0].arguments == {}


# ----------------------------------------------------------------- end-to-end


@respx.mock
async def test_http_adapter_openai_stashes_last_response_with_tool_calls() -> None:
    respx.post(_OPENAI_URL).mock(
        return_value=httpx.Response(200, json=_openai_with_tool_call(text="calling get_balance")),
    )
    adapter = HttpAdapter(
        _OPENAI_URL,
        shape="openai",
        auth_headers={"Authorization": "Bearer sk-x"},
        model="gpt-4o-mini",
    )
    try:
        text = await adapter.call("Show me my balance")
        assert "calling get_balance" in text
        snapshot = adapter._last_response
        assert isinstance(snapshot, HttpAdapterLastResponse)
        assert snapshot.text == text
        names = [c.name for c in snapshot.tool_calls]
        assert names == ["get_balance", "search_kb"]
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_anthropic_stashes_last_response_with_tool_calls() -> None:
    respx.post(_ANTHROPIC_URL).mock(
        return_value=httpx.Response(200, json=_anthropic_with_tool_use(text="ack")),
    )
    adapter = HttpAdapter(
        _ANTHROPIC_URL,
        shape="anthropic",
        auth_headers={"x-api-key": "k"},
        model="claude-3-5-sonnet-latest",
    )
    try:
        await adapter.call("Check my balance")
        snapshot = adapter._last_response
        assert snapshot is not None
        assert len(snapshot.tool_calls) == 1
        assert snapshot.tool_calls[0].name == "get_balance"
    finally:
        await adapter.aclose()


@respx.mock
async def test_http_adapter_no_tool_calls_yields_empty_tuple_no_raise() -> None:
    respx.post(_OPENAI_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "Hi there"}, "finish_reason": "stop"}],
                "model": "gpt-4o-mini",
            },
        )
    )
    adapter = HttpAdapter(_OPENAI_URL, shape="openai", model="gpt-4o-mini")
    try:
        await adapter.call("Say hi")
        snapshot = adapter._last_response
        assert snapshot is not None
        assert snapshot.tool_calls == ()
    finally:
        await adapter.aclose()


def test_tool_call_is_frozen() -> None:
    call = HttpAdapterToolCall(name="x", arguments={"a": 1})
    with pytest.raises(AttributeError):
        call.name = "y"  # type: ignore[misc]
