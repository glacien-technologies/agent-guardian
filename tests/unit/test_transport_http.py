"""Tests for HttpTransport (respx-mocked) and the HttpAdapter.send_raw seam."""

from __future__ import annotations

import httpx
import pytest
import respx

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.llm.errors import LLMResponseFormatError
from agent_guardian.transports.base import Request
from agent_guardian.transports.errors import TransportErrorCategory
from agent_guardian.transports.http import HttpTransport

ENDPOINT = "https://target.example.com/v1/chat"


def _make_transport(**kwargs: object) -> HttpTransport:
    # Fast retries: max_retries=0 so error-category tests don't spin on backoff.
    base: dict[str, object] = {
        "endpoint": ENDPOINT,
        "request_template": '{"input": "{{ prompt }}"}',
        "output_path": "$.output.text",
        "max_retries": 0,
    }
    base.update(kwargs)
    return HttpTransport(**base)  # type: ignore[arg-type]


@respx.mock
async def test_happy_path() -> None:
    route = respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "hello back"}})
    )
    t = _make_transport()
    resp = await t.send(Request(prompt="hi there"))
    assert resp.ok
    assert resp.text == "hello back"
    assert route.called
    sent = route.calls.last.request
    assert b'"input":"hi there"' in sent.content
    await t.aclose()


@respx.mock
async def test_usage_and_tool_calls_extracted() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json={
                "output": {"text": "ok"},
                "usage": {"prompt": 5, "completion": 3, "total": 8},
                "tools": [{"name": "search", "arguments": {"q": "x"}}],
            },
        )
    )
    t = _make_transport(
        usage_prompt_tokens_path="$.usage.prompt",
        usage_completion_tokens_path="$.usage.completion",
        usage_total_tokens_path="$.usage.total",
        tool_call_path="$.tools",
    )
    resp = await t.send(Request(prompt="hi"))
    assert resp.usage.prompt_tokens == 5
    assert resp.usage.total_tokens == 8
    assert resp.tool_calls[0].name == "search"
    assert resp.tool_calls[0].arguments == {"q": "x"}
    await t.aclose()


@respx.mock
async def test_session_path_extracted() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "ok"}, "sid": "S42"})
    )
    t = _make_transport(session_path="$.sid")
    resp = await t.send(Request(prompt="hi"))
    assert resp.session == "S42"
    await t.aclose()


@respx.mock
async def test_401_maps_to_auth() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(401, text="bad creds"))
    t = _make_transport()
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.AUTH
    await t.aclose()


@respx.mock
async def test_429_maps_to_rate_limit_with_retry_after() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(429, headers={"retry-after": "7"}, text="slow")
    )
    t = _make_transport()
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.RATE_LIMIT
    assert resp.error.retry_after == 7.0
    await t.aclose()


@respx.mock
async def test_timeout_maps_to_timeout() -> None:
    respx.post(ENDPOINT).mock(side_effect=httpx.ConnectTimeout("slow"))
    t = _make_transport()
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.TIMEOUT
    await t.aclose()


@respx.mock
async def test_5xx_maps_to_unreachable() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(503, text="down"))
    t = _make_transport()
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE
    await t.aclose()


@respx.mock
async def test_bad_json_maps_to_parse() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200, content=b"not json", headers={"content-type": "application/json"}
        )
    )
    t = _make_transport()
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


@respx.mock
async def test_missing_output_path_maps_to_parse() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"nope": 1}))
    t = _make_transport()
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


@respx.mock
async def test_error_path_match_on_200_maps_to_blocked() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200, json={"output": {"text": "ok"}, "refusal": "policy violation"}
        )
    )
    t = _make_transport(error_path="$.refusal")
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.BLOCKED
    assert "policy violation" in resp.error.message
    await t.aclose()


@respx.mock
async def test_error_path_absent_is_not_blocked() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    t = _make_transport(error_path="$.refusal")
    resp = await t.send(Request(prompt="hi"))
    assert resp.ok
    assert resp.text == "ok"
    await t.aclose()


async def test_bad_template_renders_to_permanent_error() -> None:
    t = HttpTransport(endpoint=ENDPOINT, request_template="not json", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PERMANENT
    await t.aclose()


def test_empty_endpoint_raises() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        HttpTransport(endpoint="")


def test_endpoint_property() -> None:
    t = _make_transport()
    assert t.endpoint == ENDPOINT


@respx.mock
async def test_float_usage_and_bool_usage_coerced() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json={
                "output": {"text": "ok"},
                "usage": {"prompt": 4.9, "completion": True, "total": "x"},
            },
        )
    )
    t = _make_transport(
        usage_prompt_tokens_path="$.usage.prompt",  # float → int(4.9) == 4
        usage_completion_tokens_path="$.usage.completion",  # bool → 0
        usage_total_tokens_path="$.usage.total",  # str → 0
    )
    resp = await t.send(Request(prompt="hi"))
    assert resp.usage.prompt_tokens == 4
    assert resp.usage.completion_tokens == 0
    assert resp.usage.total_tokens == 0
    await t.aclose()


@respx.mock
async def test_tool_call_path_absent_and_scalar_and_nondict() -> None:
    # tool_call_path present but missing in payload → empty tuple
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    t = _make_transport(tool_call_path="$.tools")
    resp = await t.send(Request(prompt="hi"))
    assert resp.tool_calls == ()
    await t.aclose()


@respx.mock
async def test_tool_call_single_object_and_nondict_items() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json={"output": {"text": "ok"}, "call": {"name": "f", "arguments": {"x": 1}}},
        )
    )
    # single object (not a list) → wrapped into one ToolCall
    t = _make_transport(tool_call_path="$.call")
    resp = await t.send(Request(prompt="hi"))
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].name == "f"
    await t.aclose()


@respx.mock
async def test_tool_call_list_with_nondict_items_skipped() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json={"output": {"text": "ok"}, "tools": ["bogus", {"name": "g"}]},
        )
    )
    t = _make_transport(tool_call_path="$.tools")
    resp = await t.send(Request(prompt="hi"))
    assert [tc.name for tc in resp.tool_calls] == ["g"]
    assert resp.tool_calls[0].arguments == {}
    await t.aclose()


@respx.mock
async def test_injected_adapter_not_closed_by_transport() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"output": {"text": "ok"}}))
    adapter = HttpAdapter(ENDPOINT, shape="generic", max_retries=0)
    t = HttpTransport(endpoint=ENDPOINT, adapter=adapter, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.text == "ok"
    await t.aclose()  # must NOT close the injected adapter
    # adapter still usable
    data = await adapter.send_raw({"k": "v"}, {})
    assert data == {"output": {"text": "ok"}}
    await adapter.aclose()


def test_registry_unknown_kind_raises() -> None:
    from agent_guardian.transports.registry import get_transport_factory

    with pytest.raises(KeyError, match="Unknown transport kind"):
        get_transport_factory("nope")


def test_registry_double_register_raises() -> None:
    from agent_guardian.transports.registry import register_transport

    with pytest.raises(ValueError, match="already registered"):
        register_transport("http", HttpTransport)


@respx.mock
async def test_registry_build_transport() -> None:
    from agent_guardian.transports.registry import build_transport, list_transport_kinds

    assert "http" in list_transport_kinds()
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"output": {"text": "via registry"}})
    )
    t = build_transport("http", endpoint=ENDPOINT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.text == "via registry"
    await t.aclose()


# --- focused tests for the HttpAdapter.send_raw seam ------------------------


@respx.mock
async def test_send_raw_happy_path() -> None:
    route = respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"echo": "value"}))
    adapter = HttpAdapter(ENDPOINT, shape="generic", max_retries=0)
    data = await adapter.send_raw({"k": "v"}, {"content-type": "application/json"})
    assert data == {"echo": "value"}
    assert route.called
    assert route.calls.last.request.content == b'{"k":"v"}'
    await adapter.aclose()


@respx.mock
async def test_send_raw_maps_status_to_llm_error() -> None:
    from agent_guardian.llm.errors import LLMAuthError

    respx.post(ENDPOINT).mock(return_value=httpx.Response(401, text="no"))
    adapter = HttpAdapter(ENDPOINT, shape="generic", max_retries=0)
    with pytest.raises(LLMAuthError):
        await adapter.send_raw({}, {})
    await adapter.aclose()


@respx.mock
async def test_send_raw_non_object_json_raises_format_error() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    adapter = HttpAdapter(ENDPOINT, shape="generic", max_retries=0)
    with pytest.raises(LLMResponseFormatError):
        await adapter.send_raw({}, {})
    await adapter.aclose()


async def test_send_raw_after_aclose_raises() -> None:
    adapter = HttpAdapter(ENDPOINT, shape="generic")
    await adapter.aclose()
    with pytest.raises(RuntimeError, match="aclose"):
        await adapter.send_raw({}, {})
