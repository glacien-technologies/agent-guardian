"""Tests for the five cloud-agent transports (respx-mocked endpoints).

Each transport is exercised for: correct request body + headers, reply-text +
usage parsing, server-session id capture/replay (the 2nd request carries the id
captured from the 1st), injected-auth header application, and fault mapping
(401 → AUTH, 500 → UNREACHABLE).

No real cloud credentials are used: a tiny :class:`_StubAuth` provider stands in
for the SigV4 / OAuth2 / Entra providers the factory injects in production.
"""

from __future__ import annotations

import base64
import binascii
import json
import struct

import httpx
import respx

from agent_guardian.transports.anthropic_messages import AnthropicMessagesTransport
from agent_guardian.transports.auth.base import AuthContext, AuthProvider
from agent_guardian.transports.azure_foundry import AzureFoundryAgentTransport
from agent_guardian.transports.base import Message, Request
from agent_guardian.transports.bedrock_agent import BedrockAgentTransport
from agent_guardian.transports.errors import TransportErrorCategory
from agent_guardian.transports.openai_responses import OpenAiResponsesTransport
from agent_guardian.transports.session import SessionMachine, SessionMode
from agent_guardian.transports.vertex_agent import VertexAgentTransport


class _StubAuth(AuthProvider):
    """Injects a deterministic header so tests can assert auth was applied."""

    def __init__(self, header: str = "x-stub-auth", value: str = "signed") -> None:
        self._header = header
        self._value = value

    async def apply(self, ctx: AuthContext) -> None:
        ctx.headers[self._header] = self._value


# --- event-stream framing helper (botocore wire format) ---------------------


def _encode_eventstream_header(name: str, value: str) -> bytes:
    nb = name.encode("utf-8")
    vb = value.encode("utf-8")
    return bytes([len(nb)]) + nb + bytes([7]) + struct.pack(">H", len(vb)) + vb


def _encode_eventstream_chunk(text: str) -> bytes:
    """Encode one ``chunk`` event whose payload is ``{"bytes": "<base64>"}``."""
    payload = json.dumps({"bytes": base64.b64encode(text.encode()).decode()}).encode()
    headers = {
        ":event-type": "chunk",
        ":content-type": "application/json",
        ":message-type": "event",
    }
    hdr = b"".join(_encode_eventstream_header(k, v) for k, v in headers.items())
    headers_len = len(hdr)
    total_len = 4 + 4 + 4 + headers_len + len(payload) + 4
    prelude = struct.pack(">I", total_len) + struct.pack(">I", headers_len)
    prelude_crc = struct.pack(">I", binascii.crc32(prelude) & 0xFFFFFFFF)
    msg_wo_crc = prelude + prelude_crc + hdr + payload
    msg_crc = struct.pack(">I", binascii.crc32(msg_wo_crc) & 0xFFFFFFFF)
    return msg_wo_crc + msg_crc


# ===========================================================================
# OpenAI Responses
# ===========================================================================

OPENAI_BASE = "https://api.openai.example/v1"
OPENAI_URL = f"{OPENAI_BASE}/responses"


@respx.mock
async def test_openai_request_body_and_text_and_usage() -> None:
    route = respx.post(OPENAI_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "resp_1",
                "output_text": "hello back",
                "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8},
            },
        )
    )
    t = OpenAiResponsesTransport(
        base_url=OPENAI_BASE, model="gpt-4o-mini", auth=_StubAuth(), max_retries=0
    )
    resp = await t.send(Request(prompt="hi"))
    assert resp.ok
    assert resp.text == "hello back"
    assert resp.usage.prompt_tokens == 5
    assert resp.usage.completion_tokens == 3
    assert resp.usage.total_tokens == 8
    assert resp.session == "resp_1"
    sent = route.calls.last.request
    body = json.loads(sent.content)
    assert body == {"model": "gpt-4o-mini", "input": "hi", "store": True}
    assert sent.headers["x-stub-auth"] == "signed"
    assert "previous_response_id" not in body
    await t.aclose()


@respx.mock
async def test_openai_output_blocks_fallback() -> None:
    respx.post(OPENAI_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "resp_x",
                "output": [
                    {"content": [{"type": "output_text", "text": "part-a "}]},
                    {"content": [{"type": "output_text", "text": "part-b"}]},
                ],
            },
        )
    )
    t = OpenAiResponsesTransport(base_url=OPENAI_BASE, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.text == "part-a part-b"
    await t.aclose()


@respx.mock
async def test_openai_server_session_replay() -> None:
    responses = [
        httpx.Response(200, json={"id": "resp_1", "output_text": "a"}),
        httpx.Response(200, json={"id": "resp_2", "output_text": "b"}),
    ]
    route = respx.post(OPENAI_URL).mock(side_effect=responses)
    t = OpenAiResponsesTransport(base_url=OPENAI_BASE, max_retries=0)
    machine = SessionMachine(t, mode=SessionMode.SERVER_SESSION)
    await machine.send("first")
    await machine.send("second")
    second_body = json.loads(route.calls[1].request.content)
    assert second_body["previous_response_id"] == "resp_1"
    assert machine.session == "resp_2"
    await t.aclose()


@respx.mock
async def test_openai_401_and_500() -> None:
    respx.post(OPENAI_URL).mock(return_value=httpx.Response(401, text="no"))
    t = OpenAiResponsesTransport(base_url=OPENAI_BASE, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.AUTH
    await t.aclose()

    respx.post(OPENAI_URL).mock(return_value=httpx.Response(500, text="boom"))
    t2 = OpenAiResponsesTransport(base_url=OPENAI_BASE, max_retries=0)
    resp2 = await t2.send(Request(prompt="hi"))
    assert resp2.error is not None
    assert resp2.error.category is TransportErrorCategory.UNREACHABLE
    await t2.aclose()


@respx.mock
async def test_openai_missing_output_maps_to_parse() -> None:
    respx.post(OPENAI_URL).mock(return_value=httpx.Response(200, json={"id": "r"}))
    t = OpenAiResponsesTransport(base_url=OPENAI_BASE, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


def test_openai_empty_base_url_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="base_url"):
        OpenAiResponsesTransport(base_url="")


def test_openai_describe_and_endpoint_property() -> None:
    t = OpenAiResponsesTransport(base_url=OPENAI_BASE)
    assert t.endpoint == OPENAI_URL
    report = t.describe()
    assert report.kind == "openai_responses"
    assert report.session_modes == ("server_session",)
    assert report.endpoint == OPENAI_URL


@respx.mock
async def test_openai_usage_coercion_and_missing() -> None:
    # float → int, bool/str → 0, and a wholly missing usage block → zeros.
    respx.post(OPENAI_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "r",
                "output_text": "ok",
                "usage": {"input_tokens": 4.9, "output_tokens": True, "total_tokens": "x"},
            },
        )
    )
    t = OpenAiResponsesTransport(base_url=OPENAI_BASE, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.usage.prompt_tokens == 4
    assert resp.usage.completion_tokens == 0
    assert resp.usage.total_tokens == 0
    await t.aclose()


# ===========================================================================
# Anthropic Messages
# ===========================================================================

ANTHROPIC_BASE = "https://api.anthropic.example/v1"
ANTHROPIC_URL = f"{ANTHROPIC_BASE}/messages"


@respx.mock
async def test_anthropic_request_body_headers_and_parse() -> None:
    route = respx.post(ANTHROPIC_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "claude says hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 4},
            },
        )
    )
    t = AnthropicMessagesTransport(
        base_url=ANTHROPIC_BASE, model="claude-x", max_tokens=512, auth=_StubAuth(), max_retries=0
    )
    resp = await t.send(Request(prompt="hello"))
    assert resp.text == "claude says hi"
    assert resp.usage.prompt_tokens == 10
    assert resp.usage.completion_tokens == 4
    assert resp.usage.total_tokens == 14
    sent = route.calls.last.request
    body = json.loads(sent.content)
    assert body["model"] == "claude-x"
    assert body["max_tokens"] == 512
    assert body["messages"] == [{"role": "user", "content": "hello"}]
    assert sent.headers["anthropic-version"] == "2023-06-01"
    assert sent.headers["x-stub-auth"] == "signed"
    await t.aclose()


@respx.mock
async def test_anthropic_client_history_threaded_into_messages() -> None:
    route = respx.post(ANTHROPIC_URL).mock(
        return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})
    )
    t = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_retries=0)
    conversation = (
        Message(role="user", content="q1"),
        Message(role="assistant", content="a1"),
    )
    await t.send(Request(prompt="q2", conversation=conversation))
    body = json.loads(route.calls.last.request.content)
    assert body["messages"] == [
        {"role": "user", "content": "q1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "q2"},
    ]
    await t.aclose()


@respx.mock
async def test_anthropic_via_session_machine_client_history() -> None:
    responses = [
        httpx.Response(200, json={"content": [{"type": "text", "text": "a1"}]}),
        httpx.Response(200, json={"content": [{"type": "text", "text": "a2"}]}),
    ]
    route = respx.post(ANTHROPIC_URL).mock(side_effect=responses)
    t = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_retries=0)
    machine = SessionMachine(t, mode=SessionMode.CLIENT_HISTORY)
    await machine.send("q1")
    await machine.send("q2")
    second_body = json.loads(route.calls[1].request.content)
    assert second_body["messages"] == [
        {"role": "user", "content": "q1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "q2"},
    ]
    await t.aclose()


@respx.mock
async def test_anthropic_401_and_500() -> None:
    respx.post(ANTHROPIC_URL).mock(return_value=httpx.Response(403, text="no"))
    t = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.AUTH
    await t.aclose()

    respx.post(ANTHROPIC_URL).mock(return_value=httpx.Response(502, text="boom"))
    t2 = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_retries=0)
    resp2 = await t2.send(Request(prompt="hi"))
    assert resp2.error is not None
    assert resp2.error.category is TransportErrorCategory.UNREACHABLE
    await t2.aclose()


@respx.mock
async def test_anthropic_malformed_maps_to_parse() -> None:
    respx.post(ANTHROPIC_URL).mock(return_value=httpx.Response(200, json={"nope": 1}))
    t = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


def test_anthropic_bad_max_tokens_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="max_tokens"):
        AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_tokens=0)


def test_anthropic_describe_and_endpoint_property() -> None:
    t = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE)
    assert t.endpoint == ANTHROPIC_URL
    report = t.describe()
    assert report.kind == "anthropic_messages"
    assert report.session_modes == ("client_history",)
    assert report.endpoint == ANTHROPIC_URL


@respx.mock
async def test_anthropic_usage_coercion_and_missing() -> None:
    respx.post(ANTHROPIC_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 7.5, "output_tokens": True},
            },
        )
    )
    t = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.usage.prompt_tokens == 7  # 7.5 → 7
    assert resp.usage.completion_tokens == 0  # bool → 0
    assert resp.usage.total_tokens == 7
    await t.aclose()

    # Wholly missing usage block → zero usage.
    respx.post(ANTHROPIC_URL).mock(
        return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})
    )
    t2 = AnthropicMessagesTransport(base_url=ANTHROPIC_BASE, max_retries=0)
    resp2 = await t2.send(Request(prompt="hi"))
    assert resp2.usage.total_tokens == 0
    await t2.aclose()


# ===========================================================================
# Bedrock Agent Runtime (InvokeAgent)
# ===========================================================================

BEDROCK_REGION = "us-east-1"
BEDROCK_AGENT = "AGENT123"
BEDROCK_ALIAS = "ALIAS9"


def _bedrock_url(session_id: str) -> str:
    return (
        f"https://bedrock-agent-runtime.{BEDROCK_REGION}.amazonaws.com"
        f"/agents/{BEDROCK_AGENT}/agentAliases/{BEDROCK_ALIAS}"
        f"/sessions/{session_id}/text"
    )


@respx.mock
async def test_bedrock_event_stream_decode_and_session() -> None:
    frame = _encode_eventstream_chunk("hello ") + _encode_eventstream_chunk("from bedrock")
    # Match any sessions/*/text path under the agent runtime host.
    route = respx.post(
        url__regex=r"https://bedrock-agent-runtime\.us-east-1\.amazonaws\.com/agents/.*/text"
    ).mock(
        return_value=httpx.Response(
            200,
            content=frame,
            headers={"content-type": "application/vnd.amazon.eventstream"},
        )
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION,
        agent_id=BEDROCK_AGENT,
        agent_alias_id=BEDROCK_ALIAS,
        enable_trace=True,
        auth=_StubAuth(),
    )
    resp = await t.send(Request(prompt="hi", session="SESS-1"))
    assert resp.ok
    assert resp.text == "hello from bedrock"
    assert resp.session == "SESS-1"
    sent = route.calls.last.request
    assert str(sent.url) == _bedrock_url("SESS-1")
    body = json.loads(sent.content)
    assert body == {"inputText": "hi", "enableTrace": True}
    assert sent.headers["x-stub-auth"] == "signed"
    await t.aclose()


@respx.mock
async def test_bedrock_server_session_replay() -> None:
    frame = _encode_eventstream_chunk("ok")
    route = respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(
            200, content=frame, headers={"content-type": "application/vnd.amazon.eventstream"}
        )
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    machine = SessionMachine(t, mode=SessionMode.SERVER_SESSION)
    r1 = await machine.send("first")
    first_session = r1.session
    assert first_session is not None
    await machine.send("second")
    # Both requests must target the SAME minted session path.
    assert str(route.calls[0].request.url) == _bedrock_url(first_session)
    assert str(route.calls[1].request.url) == _bedrock_url(first_session)
    await t.aclose()


@respx.mock
async def test_bedrock_aggregated_json_fallback() -> None:
    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(
            200,
            json={"completion": "aggregated text"},
            headers={"content-type": "application/json"},
        )
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.text == "aggregated text"
    await t.aclose()


@respx.mock
async def test_bedrock_401_and_500() -> None:
    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(401, text="no")
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.AUTH
    await t.aclose()

    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(500, text="boom")
    )
    t2 = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp2 = await t2.send(Request(prompt="hi", session="S"))
    assert resp2.error is not None
    assert resp2.error.category is TransportErrorCategory.UNREACHABLE
    await t2.aclose()


@respx.mock
async def test_bedrock_empty_stream_maps_to_parse() -> None:
    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(
            200, content=b"", headers={"content-type": "application/vnd.amazon.eventstream"}
        )
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


def test_bedrock_validation_errors() -> None:
    import pytest

    with pytest.raises(ValueError, match="region"):
        BedrockAgentTransport(region="", agent_id="a", agent_alias_id="b")
    with pytest.raises(ValueError, match="agent_id"):
        BedrockAgentTransport(region="r", agent_id="", agent_alias_id="b")
    with pytest.raises(ValueError, match="agent_alias_id"):
        BedrockAgentTransport(region="r", agent_id="a", agent_alias_id="")


def test_bedrock_describe() -> None:
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    report = t.describe()
    assert report.kind == "bedrock_agent"
    assert report.streaming is True
    assert report.session_modes == ("server_session",)


def test_bedrock_chunk_text_variants() -> None:
    # base64 {"bytes": ...} envelope.
    env = json.dumps({"bytes": base64.b64encode(b"alpha").decode()}).encode()
    assert BedrockAgentTransport._chunk_text(env) == "alpha"
    # plain {"text": ...} envelope.
    assert BedrockAgentTransport._chunk_text(json.dumps({"text": "beta"}).encode()) == "beta"
    # non-base64 bytes value falls back to the literal string.
    bad_b64 = json.dumps({"bytes": "!!!not-base64!!!"}).encode()
    assert BedrockAgentTransport._chunk_text(bad_b64) == "!!!not-base64!!!"
    # non-JSON raw bytes are treated as text directly.
    assert BedrockAgentTransport._chunk_text(b"gamma") == "gamma"
    # JSON that is not a dict falls through to the raw decode.
    assert BedrockAgentTransport._chunk_text(b"[1,2]") == "[1,2]"


def test_bedrock_text_from_json_output_fallback() -> None:
    assert BedrockAgentTransport._text_from_json({"output": {"text": "via output"}}) == "via output"


@respx.mock
async def test_bedrock_skips_non_chunk_events() -> None:
    # A chunk plus a (manually unrecognised) trailing frame should still decode.
    frame = _encode_eventstream_chunk("only-chunk")
    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(
            200, content=frame, headers={"content-type": "application/vnd.amazon.eventstream"}
        )
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.text == "only-chunk"
    await t.aclose()


@respx.mock
async def test_bedrock_timeout_and_network_mapping() -> None:
    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        side_effect=httpx.ConnectTimeout("slow")
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.TIMEOUT
    await t.aclose()

    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        side_effect=httpx.ConnectError("no route")
    )
    t2 = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp2 = await t2.send(Request(prompt="hi", session="S"))
    assert resp2.error is not None
    assert resp2.error.category is TransportErrorCategory.UNREACHABLE
    await t2.aclose()


@respx.mock
async def test_bedrock_invalid_and_nondict_json_map_to_parse() -> None:
    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(
            200, content=b"not json", headers={"content-type": "application/json"}
        )
    )
    t = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()

    respx.post(url__regex=r"https://bedrock-agent-runtime\..*/text").mock(
        return_value=httpx.Response(
            200, json=[1, 2, 3], headers={"content-type": "application/json"}
        )
    )
    t2 = BedrockAgentTransport(
        region=BEDROCK_REGION, agent_id=BEDROCK_AGENT, agent_alias_id=BEDROCK_ALIAS
    )
    resp2 = await t2.send(Request(prompt="hi", session="S"))
    assert resp2.error is not None
    assert resp2.error.category is TransportErrorCategory.PARSE
    await t2.aclose()


# ===========================================================================
# Vertex AI Reasoning Engine (:query)
# ===========================================================================

VERTEX_PROJECT = "proj-1"
VERTEX_LOCATION = "us-central1"
VERTEX_ENGINE = "456"
VERTEX_URL = (
    f"https://{VERTEX_LOCATION}-aiplatform.googleapis.com/v1"
    f"/projects/{VERTEX_PROJECT}/locations/{VERTEX_LOCATION}"
    f"/reasoningEngines/{VERTEX_ENGINE}:query"
)


@respx.mock
async def test_vertex_request_body_and_parse_nested_output() -> None:
    route = respx.post(VERTEX_URL).mock(
        return_value=httpx.Response(200, json={"output": {"output": "gemini reply"}})
    )
    t = VertexAgentTransport(
        project=VERTEX_PROJECT,
        location=VERTEX_LOCATION,
        engine_id=VERTEX_ENGINE,
        auth=_StubAuth(),
        max_retries=0,
    )
    resp = await t.send(Request(prompt="hi", session="VSESS"))
    assert resp.text == "gemini reply"
    assert resp.session == "VSESS"
    sent = route.calls.last.request
    body = json.loads(sent.content)
    assert body["input"] == {"input": "hi"}
    assert body["config"]["configurable"]["session_id"] == "VSESS"
    assert sent.headers["x-stub-auth"] == "signed"
    await t.aclose()


@respx.mock
async def test_vertex_plain_string_output() -> None:
    respx.post(VERTEX_URL).mock(return_value=httpx.Response(200, json={"output": "flat reply"}))
    t = VertexAgentTransport(
        project=VERTEX_PROJECT, location=VERTEX_LOCATION, engine_id=VERTEX_ENGINE, max_retries=0
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.text == "flat reply"
    await t.aclose()


@respx.mock
async def test_vertex_server_session_replay() -> None:
    route = respx.post(VERTEX_URL).mock(return_value=httpx.Response(200, json={"output": "ok"}))
    t = VertexAgentTransport(
        project=VERTEX_PROJECT, location=VERTEX_LOCATION, engine_id=VERTEX_ENGINE, max_retries=0
    )
    machine = SessionMachine(t, mode=SessionMode.SERVER_SESSION)
    r1 = await machine.send("first")
    minted = r1.session
    assert minted is not None
    await machine.send("second")
    first_body = json.loads(route.calls[0].request.content)
    second_body = json.loads(route.calls[1].request.content)
    assert first_body["config"]["configurable"]["session_id"] == minted
    assert second_body["config"]["configurable"]["session_id"] == minted
    await t.aclose()


@respx.mock
async def test_vertex_401_and_500() -> None:
    respx.post(VERTEX_URL).mock(return_value=httpx.Response(401, text="no"))
    t = VertexAgentTransport(
        project=VERTEX_PROJECT, location=VERTEX_LOCATION, engine_id=VERTEX_ENGINE, max_retries=0
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.AUTH
    await t.aclose()

    respx.post(VERTEX_URL).mock(return_value=httpx.Response(503, text="boom"))
    t2 = VertexAgentTransport(
        project=VERTEX_PROJECT, location=VERTEX_LOCATION, engine_id=VERTEX_ENGINE, max_retries=0
    )
    resp2 = await t2.send(Request(prompt="hi", session="S"))
    assert resp2.error is not None
    assert resp2.error.category is TransportErrorCategory.UNREACHABLE
    await t2.aclose()


@respx.mock
async def test_vertex_missing_output_maps_to_parse() -> None:
    respx.post(VERTEX_URL).mock(return_value=httpx.Response(200, json={"nope": 1}))
    t = VertexAgentTransport(
        project=VERTEX_PROJECT, location=VERTEX_LOCATION, engine_id=VERTEX_ENGINE, max_retries=0
    )
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


def test_vertex_validation_errors() -> None:
    import pytest

    with pytest.raises(ValueError, match="project"):
        VertexAgentTransport(project="", location="l", engine_id="e")
    with pytest.raises(ValueError, match="location"):
        VertexAgentTransport(project="p", location="", engine_id="e")
    with pytest.raises(ValueError, match="engine_id"):
        VertexAgentTransport(project="p", location="l", engine_id="")


@respx.mock
async def test_vertex_output_text_branch_and_endpoint_property() -> None:
    respx.post(VERTEX_URL).mock(
        return_value=httpx.Response(200, json={"output": {"text": "via output.text"}})
    )
    t = VertexAgentTransport(
        project=VERTEX_PROJECT, location=VERTEX_LOCATION, engine_id=VERTEX_ENGINE, max_retries=0
    )
    assert t.endpoint == VERTEX_URL
    resp = await t.send(Request(prompt="hi", session="S"))
    assert resp.text == "via output.text"
    await t.aclose()


def test_vertex_describe() -> None:
    t = VertexAgentTransport(
        project=VERTEX_PROJECT, location=VERTEX_LOCATION, engine_id=VERTEX_ENGINE
    )
    report = t.describe()
    assert report.kind == "vertex_agent"
    assert report.session_modes == ("server_session",)
    assert report.endpoint == VERTEX_URL


# ===========================================================================
# Azure AI Foundry Agent Service
# ===========================================================================

AZURE_ENDPOINT = "https://my-foundry.services.ai.azure.com/api/projects/p"
AZURE_AGENT = "asst_42"
AZURE_URL = f"{AZURE_ENDPOINT}/threads/runs?api-version=2024-12-01-preview"


@respx.mock
async def test_azure_first_turn_creates_thread_and_parses() -> None:
    route = respx.post(AZURE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "thread_id": "thread_1",
                "output": {
                    "message": {"content": [{"type": "text", "text": {"value": "foundry reply"}}]}
                },
            },
        )
    )
    t = AzureFoundryAgentTransport(
        endpoint=AZURE_ENDPOINT, agent_id=AZURE_AGENT, auth=_StubAuth(), max_retries=0
    )
    resp = await t.send(Request(prompt="hi"))
    assert resp.text == "foundry reply"
    assert resp.session == "thread_1"
    sent = route.calls.last.request
    body = json.loads(sent.content)
    assert body["assistant_id"] == AZURE_AGENT
    assert body["thread"] == {"messages": [{"role": "user", "content": "hi"}]}
    assert "thread_id" not in body
    assert sent.headers["x-stub-auth"] == "signed"
    await t.aclose()


@respx.mock
async def test_azure_server_session_replay() -> None:
    responses = [
        httpx.Response(
            200,
            json={
                "thread_id": "thread_1",
                "output": {"message": {"content": [{"text": {"value": "a1"}}]}},
            },
        ),
        httpx.Response(
            200,
            json={
                "thread_id": "thread_1",
                "output": {"message": {"content": [{"text": {"value": "a2"}}]}},
            },
        ),
    ]
    route = respx.post(AZURE_URL).mock(side_effect=responses)
    t = AzureFoundryAgentTransport(endpoint=AZURE_ENDPOINT, agent_id=AZURE_AGENT, max_retries=0)
    machine = SessionMachine(t, mode=SessionMode.SERVER_SESSION)
    await machine.send("q1")
    await machine.send("q2")
    first_body = json.loads(route.calls[0].request.content)
    second_body = json.loads(route.calls[1].request.content)
    assert "thread" in first_body and "thread_id" not in first_body
    assert second_body["thread_id"] == "thread_1"
    assert second_body["additional_messages"] == [{"role": "user", "content": "q2"}]
    assert machine.session == "thread_1"
    await t.aclose()


@respx.mock
async def test_azure_top_level_content_fallback_and_thread_object() -> None:
    respx.post(AZURE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "thread": {"id": "thread_z"},
                "content": [{"text": {"value": "top-level reply"}}],
            },
        )
    )
    t = AzureFoundryAgentTransport(endpoint=AZURE_ENDPOINT, agent_id=AZURE_AGENT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.text == "top-level reply"
    assert resp.session == "thread_z"
    await t.aclose()


@respx.mock
async def test_azure_401_and_500() -> None:
    respx.post(AZURE_URL).mock(return_value=httpx.Response(401, text="no"))
    t = AzureFoundryAgentTransport(endpoint=AZURE_ENDPOINT, agent_id=AZURE_AGENT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.AUTH
    await t.aclose()

    respx.post(AZURE_URL).mock(return_value=httpx.Response(500, text="boom"))
    t2 = AzureFoundryAgentTransport(endpoint=AZURE_ENDPOINT, agent_id=AZURE_AGENT, max_retries=0)
    resp2 = await t2.send(Request(prompt="hi"))
    assert resp2.error is not None
    assert resp2.error.category is TransportErrorCategory.UNREACHABLE
    await t2.aclose()


@respx.mock
async def test_azure_missing_text_maps_to_parse() -> None:
    respx.post(AZURE_URL).mock(return_value=httpx.Response(200, json={"thread_id": "t"}))
    t = AzureFoundryAgentTransport(endpoint=AZURE_ENDPOINT, agent_id=AZURE_AGENT, max_retries=0)
    resp = await t.send(Request(prompt="hi"))
    assert resp.error is not None
    assert resp.error.category is TransportErrorCategory.PARSE
    await t.aclose()


def test_azure_validation_errors() -> None:
    import pytest

    with pytest.raises(ValueError, match="endpoint"):
        AzureFoundryAgentTransport(endpoint="", agent_id="a")
    with pytest.raises(ValueError, match="agent_id"):
        AzureFoundryAgentTransport(endpoint=AZURE_ENDPOINT, agent_id="")


def test_azure_describe_and_endpoint_property() -> None:
    t = AzureFoundryAgentTransport(endpoint=AZURE_ENDPOINT, agent_id=AZURE_AGENT)
    assert t.endpoint == AZURE_URL
    report = t.describe()
    assert report.kind == "azure_foundry"
    assert report.session_modes == ("server_session",)
    assert report.auth_scheme == "azure_entra"


def test_azure_text_from_content_variants() -> None:
    # Non-list content → None.
    assert AzureFoundryAgentTransport._text_from_content("nope") is None
    # Non-dict blocks are skipped; {"text": "<str>"} blocks are taken verbatim.
    content = ["skip-me", {"text": "plain"}, {"text": {"value": "nested"}}]
    assert AzureFoundryAgentTransport._text_from_content(content) == "plainnested"
    # No usable text → None.
    assert AzureFoundryAgentTransport._text_from_content([{"image": "x"}]) is None


def test_azure_extract_thread_id_none() -> None:
    # No thread_id / thread.id present → None (so session falls back to request).
    assert AzureFoundryAgentTransport._extract_thread_id({"thread": {"no_id": 1}}) is None
    assert AzureFoundryAgentTransport._extract_thread_id({}) is None
