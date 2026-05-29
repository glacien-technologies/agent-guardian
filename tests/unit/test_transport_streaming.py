"""Tests for SSE streaming accumulation and unsupported-format stubs."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from agent_guardian.transports.streaming import (
    accumulate_chunked,
    accumulate_chunked_async,
    accumulate_sse,
    accumulate_sse_async,
    accumulate_websocket,
    iter_sse_events,
)

SSE_LINES = [
    'data: {"delta": "Hel"}',
    "",
    'data: {"delta": "lo"}',
    "",
    'data: {"delta": " world"}',
    "",
    "data: [DONE]",
    "",
]


def test_iter_sse_events_groups_and_stops_on_done() -> None:
    events = iter_sse_events(SSE_LINES)
    assert events == [
        '{"delta": "Hel"}',
        '{"delta": "lo"}',
        '{"delta": " world"}',
    ]


def test_iter_sse_events_skips_comments_and_joins_multiline() -> None:
    lines = [
        ": this is a comment",
        "data: line1",
        "data: line2",
        "",
    ]
    events = iter_sse_events(lines)
    assert events == ["line1\nline2"]


def test_accumulate_sse_concatenates_deltas() -> None:
    result = accumulate_sse(SSE_LINES, delta_path="$.delta")
    assert result.text == "Hello world"
    assert result.done is True
    assert len(result.events) == 3


def test_accumulate_sse_custom_delta_path() -> None:
    lines = [
        'data: {"choices": [{"delta": {"content": "a"}}]}',
        "",
        'data: {"choices": [{"delta": {"content": "b"}}]}',
        "",
        "data: [DONE]",
        "",
    ]
    result = accumulate_sse(lines, delta_path="$.choices[0].delta.content")
    assert result.text == "ab"


def test_accumulate_sse_ignores_bad_json() -> None:
    lines = ['data: {"delta": "ok"}', "", "data: not-json", "", "data: [DONE]", ""]
    result = accumulate_sse(lines, delta_path="$.delta")
    assert result.text == "ok"


def test_accumulate_sse_ignores_non_string_delta() -> None:
    lines = ['data: {"delta": 5}', "", 'data: {"delta": "x"}', ""]
    result = accumulate_sse(lines, delta_path="$.delta")
    assert result.text == "x"


async def test_accumulate_sse_async() -> None:
    async def gen() -> AsyncIterator[str]:
        for line in SSE_LINES:
            yield line

    result = await accumulate_sse_async(gen(), delta_path="$.delta")
    assert result.text == "Hello world"
    assert result.done is True


async def test_accumulate_sse_async_no_done_sentinel() -> None:
    async def gen() -> AsyncIterator[str]:
        yield 'data: {"delta": "a"}'
        yield ""
        yield 'data: {"delta": "b"}'
        # stream ends without a blank line / [DONE]

    result = await accumulate_sse_async(gen(), delta_path="$.delta")
    assert result.text == "ab"
    assert result.done is True


async def test_accumulate_sse_async_skips_comments_and_blank_runs() -> None:
    async def gen() -> AsyncIterator[str]:
        yield ": keep-alive comment"
        yield ""  # blank with empty buffer → no-op
        yield 'data: {"delta": "x"}'
        yield ""
        yield 'data: {"delta": "y"}'
        yield ""
        yield "data: [DONE]"

    result = await accumulate_sse_async(gen(), delta_path="$.delta")
    assert result.text == "xy"
    assert result.done is True


async def test_accumulate_sse_async_done_flushes_pending_buffer() -> None:
    async def gen() -> AsyncIterator[str]:
        yield 'data: {"delta": "a"}'
        yield "data: [DONE]"  # DONE arrives with a pending buffered event

    result = await accumulate_sse_async(gen(), delta_path="$.delta")
    assert result.text == "a"
    assert result.done is True


def test_iter_sse_events_strips_only_one_leading_space() -> None:
    events = iter_sse_events(["data:  two-spaces", ""])
    assert events == [" two-spaces"]


def test_accumulate_chunked_json_lines() -> None:
    chunks = ['{"delta": "Hel"}', '{"delta": "lo"}', '{"delta": " world"}']
    result = accumulate_chunked(chunks, delta_path="$.delta")
    assert result.text == "Hello world"
    assert result.done is True
    assert len(result.events) == 3


def test_accumulate_chunked_json_lines_skips_blank_and_malformed() -> None:
    chunks = ['{"delta": "ok"}', "", "   ", "not-json", '{"delta": "!"}']
    result = accumulate_chunked(chunks, delta_path="$.delta")
    assert result.text == "ok!"
    assert len(result.events) == 2


def test_accumulate_chunked_custom_delta_path() -> None:
    chunks = [
        '{"choices": [{"delta": {"content": "a"}}]}',
        '{"choices": [{"delta": {"content": "b"}}]}',
    ]
    result = accumulate_chunked(chunks, delta_path="$.choices[0].delta.content")
    assert result.text == "ab"


def test_accumulate_chunked_raw_concatenation() -> None:
    chunks = ["Hello", ", ", "world", "!"]
    result = accumulate_chunked(chunks, delta_path=None)
    assert result.text == "Hello, world!"
    assert result.events == []
    assert result.done is True


def test_accumulate_chunked_ignores_non_string_delta() -> None:
    chunks = ['{"delta": 5}', '{"delta": "x"}']
    result = accumulate_chunked(chunks, delta_path="$.delta")
    assert result.text == "x"


def test_accumulate_chunked_non_dict_json_skipped() -> None:
    chunks = ["[1, 2, 3]", '{"delta": "y"}']
    result = accumulate_chunked(chunks, delta_path="$.delta")
    assert result.text == "y"
    assert len(result.events) == 1


async def test_accumulate_chunked_async() -> None:
    async def gen() -> AsyncIterator[str]:
        for chunk in ['{"delta": "a"}', '{"delta": "b"}']:
            yield chunk

    result = await accumulate_chunked_async(gen(), delta_path="$.delta")
    assert result.text == "ab"
    assert result.done is True


async def test_accumulate_chunked_async_raw() -> None:
    async def gen() -> AsyncIterator[str]:
        for chunk in ["foo", "bar"]:
            yield chunk

    result = await accumulate_chunked_async(gen(), delta_path=None)
    assert result.text == "foobar"


def test_websocket_not_implemented() -> None:
    with pytest.raises(NotImplementedError, match="websocket"):
        accumulate_websocket()
