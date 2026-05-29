"""Tests for McpTransport — a JSON-RPC 2.0 client over MCP Streamable HTTP.

The MCP endpoint is respx-mocked. Because all three MCP methods (``initialize``,
``tools/list``, ``tools/call``) hit the *same* URL, the mock inspects the posted
JSON-RPC envelope's ``method`` and returns the matching ``result`` envelope.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from agent_guardian.transports.auth.base import AuthContext, AuthProvider
from agent_guardian.transports.base import Request
from agent_guardian.transports.errors import TransportErrorCategory
from agent_guardian.transports.mcp import McpTransport

ENDPOINT = "https://mcp.example.com/rpc"


def _rpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


_INIT_RESULT = {
    "protocolVersion": "2025-06-18",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "demo-mcp", "version": "1.0"},
}

_TOOLS = [
    {"name": "echo", "description": "echo back", "inputSchema": {"type": "object"}},
    {"name": "search", "description": "search", "inputSchema": {"type": "object"}},
    {"name": "delete_everything", "description": "danger", "inputSchema": {"type": "object"}},
]


def _make_router(
    *,
    session_header: str | None = None,
    tools: list[dict[str, Any]] | None = None,
) -> Any:
    """Return a respx side-effect that dispatches on the JSON-RPC ``method``.

    When ``session_header`` is set, the ``initialize`` response carries an
    ``Mcp-Session-Id`` header so we can assert it is captured + replayed.
    """
    tool_list = tools if tools is not None else _TOOLS

    def _handler(request: httpx.Request) -> httpx.Response:
        envelope = json.loads(request.content)
        method = envelope["method"]
        req_id = envelope["id"]
        if method == "initialize":
            headers: dict[str, str] = {}
            if session_header is not None:
                headers["Mcp-Session-Id"] = session_header
            return httpx.Response(200, json=_rpc_result(req_id, _INIT_RESULT), headers=headers)
        if method == "tools/list":
            return httpx.Response(200, json=_rpc_result(req_id, {"tools": tool_list}))
        if method == "tools/call":
            name = envelope["params"]["name"]
            return httpx.Response(
                200,
                json=_rpc_result(
                    req_id,
                    {"content": [{"type": "text", "text": f"ran {name}"}]},
                ),
            )
        return httpx.Response(400, json=_rpc_error(req_id, -32601, "method not found"))

    return _handler


@respx.mock
async def test_initialize_handshake() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, max_retries=0)
    result = await t.initialize()
    assert result["protocolVersion"] == "2025-06-18"
    assert t._server_capabilities == {"tools": {}}
    # The posted envelope is a well-formed JSON-RPC 2.0 'initialize' request.
    sent = json.loads(route.calls.last.request.content)
    assert sent["jsonrpc"] == "2.0"
    assert sent["method"] == "initialize"
    assert sent["params"]["clientInfo"]["name"] == "agent-guardian"
    assert sent["params"]["protocolVersion"] == "2025-06-18"
    await t.aclose()


@respx.mock
async def test_list_tools_parses_names() -> None:
    respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, max_retries=0)
    await t.initialize()
    names = await t.list_tools()
    assert names == ("echo", "search", "delete_everything")
    assert t.discovered_tools == names
    await t.aclose()


@respx.mock
async def test_send_calls_entry_tool() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, entry_tool="search", prompt_argument="query", max_retries=0)
    resp = await t.send(Request(prompt="find me cats"))
    assert resp.ok
    assert resp.text == "ran search"
    assert resp.tool_calls[0].name == "search"
    assert resp.tool_calls[0].arguments == {"query": "find me cats"}
    # The last POST was a tools/call for the entry tool with our prompt argument.
    last = json.loads(route.calls.last.request.content)
    assert last["method"] == "tools/call"
    assert last["params"] == {"name": "search", "arguments": {"query": "find me cats"}}
    await t.aclose()


@respx.mock
async def test_send_uses_first_discovered_tool_when_no_entry() -> None:
    respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.ok
    # First discovered tool is "echo".
    assert resp.text == "ran echo"
    assert resp.tool_calls[0].name == "echo"
    await t.aclose()


@respx.mock
async def test_no_tools_returns_protocol_error() -> None:
    respx.post(ENDPOINT).mock(side_effect=_make_router(tools=[]))
    t = McpTransport(ENDPOINT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert "no tools" in resp.error.message
    await t.aclose()


@respx.mock
async def test_tool_gate_blocks_destructive_tool_live() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(
        ENDPOINT,
        entry_tool="delete_everything",
        max_retries=0,
        tool_gate=lambda n: n != "delete_everything",
    )
    resp = await t.send(Request(prompt="rm -rf /"))
    # Blocked: a benign note, a recorded ToolCall, and NO transport fault.
    assert resp.ok
    assert "blocked by RoE" in resp.text
    assert resp.tool_calls[0].name == "delete_everything"
    # The proof it was blocked LIVE: only initialize + tools/list were POSTed —
    # no tools/call ever reached the server.
    methods = [json.loads(c.request.content)["method"] for c in route.calls]
    assert "tools/call" not in methods
    assert methods == ["initialize", "tools/list"]
    await t.aclose()


@respx.mock
async def test_tool_gate_allows_permitted_tool() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(
        ENDPOINT,
        entry_tool="echo",
        max_retries=0,
        tool_gate=lambda n: n != "delete_everything",
    )
    resp = await t.send(Request(prompt="hello"))
    assert resp.ok
    assert resp.text == "ran echo"
    methods = [json.loads(c.request.content)["method"] for c in route.calls]
    assert "tools/call" in methods
    await t.aclose()


@respx.mock
async def test_session_id_captured_and_replayed() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router(session_header="SESS-123"))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)

    first = await t.send(Request(prompt="one"))
    assert first.ok
    assert first.session == "SESS-123"
    assert t._session_id == "SESS-123"

    # First call: initialize had no inbound Mcp-Session-Id header.
    init_req = route.calls[0].request
    assert "Mcp-Session-Id" not in init_req.headers

    # Second send: the captured id is replayed on every subsequent request.
    second = await t.send(Request(prompt="two"))
    assert second.session == "SESS-123"
    replayed = route.calls.last.request
    assert replayed.headers["Mcp-Session-Id"] == "SESS-123"
    await t.aclose()


@respx.mock
async def test_jsonrpc_error_maps_to_response_error() -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        env = json.loads(request.content)
        method = env["method"]
        req_id = env["id"]
        if method == "initialize":
            return httpx.Response(200, json=_rpc_result(req_id, _INIT_RESULT))
        if method == "tools/list":
            return httpx.Response(200, json=_rpc_result(req_id, {"tools": _TOOLS}))
        # tools/call returns a JSON-RPC error member.
        return httpx.Response(200, json=_rpc_error(req_id, -32000, "internal tool failure"))

    respx.post(ENDPOINT).mock(side_effect=_handler)
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PERMANENT
    assert "internal tool failure" in resp.error.message
    assert resp.error.status_code == -32000
    await t.aclose()


@respx.mock
async def test_jsonrpc_error_denial_maps_to_blocked() -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        env = json.loads(request.content)
        method = env["method"]
        req_id = env["id"]
        if method == "initialize":
            return httpx.Response(200, json=_rpc_result(req_id, _INIT_RESULT))
        if method == "tools/list":
            return httpx.Response(200, json=_rpc_result(req_id, {"tools": _TOOLS}))
        return httpx.Response(200, json=_rpc_error(req_id, -32001, "permission denied"))

    respx.post(ENDPOINT).mock(side_effect=_handler)
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.BLOCKED
    await t.aclose()


@respx.mock
async def test_tool_call_is_error_maps_to_blocked() -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        env = json.loads(request.content)
        method = env["method"]
        req_id = env["id"]
        if method == "initialize":
            return httpx.Response(200, json=_rpc_result(req_id, _INIT_RESULT))
        if method == "tools/list":
            return httpx.Response(200, json=_rpc_result(req_id, {"tools": _TOOLS}))
        return httpx.Response(
            200,
            json=_rpc_result(
                req_id,
                {"content": [{"type": "text", "text": "refused"}], "isError": True},
            ),
        )

    respx.post(ENDPOINT).mock(side_effect=_handler)
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.BLOCKED
    assert "refused" in resp.error.message
    # A ToolCall is still recorded for the receipt.
    assert resp.tool_calls[0].name == "echo"
    await t.aclose()


@respx.mock
async def test_401_maps_to_auth() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(401, text="bad token"))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.AUTH
    await t.aclose()


@respx.mock
async def test_500_maps_to_unreachable() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(500, text="boom"))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE
    await t.aclose()


class _BearerAuth(AuthProvider):
    """Minimal bearer provider to assert the Authorization header path."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def apply(self, ctx: AuthContext) -> None:
        ctx.headers["Authorization"] = f"Bearer {self._token}"


@respx.mock
async def test_auth_applied_to_authorization_header_not_query() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, entry_tool="echo", auth=_BearerAuth("tok-abc"), max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.ok
    for call in route.calls:
        req = call.request
        assert req.headers["Authorization"] == "Bearer tok-abc"
        # Bearer token MUST be in the header, never the query string.
        assert "tok-abc" not in str(req.url)
        assert req.url.query == b""
    await t.aclose()


@respx.mock
async def test_lazy_discovery_runs_once() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    await t.send(Request(prompt="one"))
    await t.send(Request(prompt="two"))
    methods = [json.loads(c.request.content)["method"] for c in route.calls]
    # initialize + tools/list happen exactly once; two tools/call follow.
    assert methods.count("initialize") == 1
    assert methods.count("tools/list") == 1
    assert methods.count("tools/call") == 2
    await t.aclose()


@respx.mock
async def test_describe_reports_tools_and_session_mode() -> None:
    respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, entry_tool="echo", auth=_BearerAuth("x"), max_retries=0)
    # Before discovery: still reports MCP shape, tool surface, server session.
    cap = t.describe()
    assert cap.kind == "mcp"
    assert cap.supports_tools is True
    assert "server_session" in cap.session_modes
    assert cap.auth_scheme == "_Bearer"
    assert cap.endpoint == ENDPOINT
    # After discovery, discovered_tools is populated.
    await t.send(Request(prompt="hi"))
    assert t.discovered_tools == ("echo", "search", "delete_everything")
    await t.aclose()


@respx.mock
async def test_jsonrpc_id_increments() -> None:
    route = respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    await t.send(Request(prompt="hi"))
    ids = [json.loads(c.request.content)["id"] for c in route.calls]
    # initialize=1, tools/list=2, tools/call=3 — strictly increasing.
    assert ids == [1, 2, 3]
    await t.aclose()


@respx.mock
async def test_timeout_maps_to_timeout() -> None:
    respx.post(ENDPOINT).mock(side_effect=httpx.ReadTimeout("slow"))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.TIMEOUT
    await t.aclose()


@respx.mock
async def test_network_error_maps_to_unreachable() -> None:
    respx.post(ENDPOINT).mock(side_effect=httpx.ConnectError("no route"))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE
    await t.aclose()


@respx.mock
async def test_429_maps_to_rate_limit_with_retry_after() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(429, headers={"retry-after": "7"}, text="slow down")
    )
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert not resp.ok
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.RATE_LIMIT
    assert resp.error.retry_after == 7.0
    await t.aclose()


@respx.mock
async def test_429_unparseable_retry_after_is_ignored() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(429, headers={"retry-after": "soon"}, text="x")
    )
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.RATE_LIMIT
    assert resp.error.retry_after is None
    await t.aclose()


@respx.mock
async def test_408_maps_to_unreachable() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(408, text="request timeout"))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE
    await t.aclose()


@respx.mock
async def test_404_maps_to_permanent() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(404, text="not found"))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PERMANENT
    await t.aclose()


@respx.mock
async def test_invalid_json_maps_to_parse() -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200, content=b"not json", headers={"content-type": "application/json"}
        )
    )
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


@respx.mock
async def test_non_object_top_level_maps_to_parse() -> None:
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json=["not", "an", "object"]))
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


@respx.mock
async def test_missing_result_object_maps_to_parse() -> None:
    # A 200 JSON-RPC envelope with neither 'result' nor 'error'.
    respx.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1}))
    t = McpTransport(ENDPOINT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


@respx.mock
async def test_discovery_jsonrpc_error_surfaces_on_send() -> None:
    # initialize itself returns a JSON-RPC error -> discovery fails inside send().
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(200, json=_rpc_error(1, -32603, "internal error"))
    )
    t = McpTransport(ENDPOINT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PERMANENT
    assert "internal error" in resp.error.message
    await t.aclose()


@respx.mock
async def test_discovery_transport_fault_surfaces_on_send() -> None:
    # initialize returns 500 -> mapped transport fault folded into Response.
    respx.post(ENDPOINT).mock(return_value=httpx.Response(500, text="down"))
    t = McpTransport(ENDPOINT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE
    await t.aclose()


@respx.mock
async def test_malformed_tool_entries_are_skipped() -> None:
    bad_tools: list[Any] = [
        "not-a-dict",
        {"description": "no name key"},
        {"name": ""},
        {"name": 42},
        {"name": "good"},
    ]
    respx.post(ENDPOINT).mock(side_effect=_make_router(tools=bad_tools))
    t = McpTransport(ENDPOINT, max_retries=0)
    await t.initialize()
    names = await t.list_tools()
    assert names == ("good",)
    await t.aclose()


@respx.mock
async def test_tools_list_non_list_yields_no_tools() -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        env = json.loads(request.content)
        if env["method"] == "initialize":
            return httpx.Response(200, json=_rpc_result(env["id"], _INIT_RESULT))
        # tools/list returns a 'tools' that is not a list.
        return httpx.Response(200, json=_rpc_result(env["id"], {"tools": {"oops": 1}}))

    respx.post(ENDPOINT).mock(side_effect=_handler)
    t = McpTransport(ENDPOINT, max_retries=0)
    await t.initialize()
    assert await t.list_tools() == ()
    await t.aclose()


@respx.mock
async def test_extract_text_ignores_non_text_blocks() -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        env = json.loads(request.content)
        method = env["method"]
        if method == "initialize":
            return httpx.Response(200, json=_rpc_result(env["id"], _INIT_RESULT))
        if method == "tools/list":
            return httpx.Response(200, json=_rpc_result(env["id"], {"tools": _TOOLS}))
        return httpx.Response(
            200,
            json=_rpc_result(
                env["id"],
                {
                    "content": [
                        {"type": "image", "data": "..."},
                        {"type": "text", "text": "part-A "},
                        "not-a-block",
                        {"type": "text", "text": "part-B"},
                    ]
                },
            ),
        )

    respx.post(ENDPOINT).mock(side_effect=_handler)
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.ok
    assert resp.text == "part-A part-B"
    await t.aclose()


@respx.mock
async def test_content_not_a_list_yields_empty_text() -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        env = json.loads(request.content)
        method = env["method"]
        if method == "initialize":
            return httpx.Response(200, json=_rpc_result(env["id"], _INIT_RESULT))
        if method == "tools/list":
            return httpx.Response(200, json=_rpc_result(env["id"], {"tools": _TOOLS}))
        return httpx.Response(200, json=_rpc_result(env["id"], {"content": "oops"}))

    respx.post(ENDPOINT).mock(side_effect=_handler)
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.ok
    assert resp.text == ""
    await t.aclose()


@respx.mock
async def test_injected_client_not_closed_by_aclose() -> None:
    client = httpx.AsyncClient()
    respx.post(ENDPOINT).mock(side_effect=_make_router())
    t = McpTransport(ENDPOINT, entry_tool="echo", client=client, max_retries=0)
    await t.send(Request(prompt="hi"))
    await t.aclose()
    # We do not own the injected client, so it stays open for the caller.
    assert not client.is_closed
    await client.aclose()


@respx.mock
async def test_tools_call_transport_fault_after_successful_discovery() -> None:
    # initialize + tools/list succeed; only the tools/call POST faults (503).
    def _handler(request: httpx.Request) -> httpx.Response:
        env = json.loads(request.content)
        method = env["method"]
        if method == "initialize":
            return httpx.Response(200, json=_rpc_result(env["id"], _INIT_RESULT))
        if method == "tools/list":
            return httpx.Response(200, json=_rpc_result(env["id"], {"tools": _TOOLS}))
        return httpx.Response(503, text="overloaded")

    respx.post(ENDPOINT).mock(side_effect=_handler)
    t = McpTransport(ENDPOINT, entry_tool="echo", max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.UNREACHABLE
    await t.aclose()


async def test_endpoint_property() -> None:
    t = McpTransport(ENDPOINT)
    assert t.endpoint == ENDPOINT
    await t.aclose()


def test_empty_endpoint_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty endpoint"):
        McpTransport("")
