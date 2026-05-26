"""Tests for Bedrock request/response shaping (auth lands in M9)."""

from __future__ import annotations

import pytest

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.bedrock import (
    BedrockClient,
    build_bedrock_payload,
    map_bedrock_response,
)
from agent_guardian.llm.errors import LLMResponseFormatError


def test_build_bedrock_payload_simple() -> None:
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="anthropic.claude-3-5-sonnet-20240620-v1:0",
    )
    payload = build_bedrock_payload(req)
    assert payload["messages"] == [{"role": "user", "content": [{"text": "hello"}]}]
    assert payload["inferenceConfig"]["maxTokens"] == 1024
    assert payload["inferenceConfig"]["temperature"] == 0.7
    assert "system" not in payload


def test_build_bedrock_payload_separates_system() -> None:
    req = LLMRequest(
        messages=[
            LLMMessage(role="system", content="be polite"),
            LLMMessage(role="system", content="also be brief"),
            LLMMessage(role="user", content="hi"),
        ],
        model="m",
    )
    payload = build_bedrock_payload(req)
    assert payload["system"] == [{"text": "be polite"}, {"text": "also be brief"}]
    assert payload["messages"] == [{"role": "user", "content": [{"text": "hi"}]}]


def test_build_bedrock_payload_stop_sequences() -> None:
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="m",
        stop=["END"],
    )
    payload = build_bedrock_payload(req)
    assert payload["inferenceConfig"]["stopSequences"] == ["END"]


def test_map_bedrock_response_happy_path() -> None:
    data = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "hi there"}],
            }
        },
        "usage": {"inputTokens": 5, "outputTokens": 3, "totalTokens": 8},
        "stopReason": "end_turn",
    }
    resp = map_bedrock_response("m", data)
    assert resp.text == "hi there"
    assert resp.provider == "bedrock"
    assert resp.usage.prompt_tokens == 5
    assert resp.usage.completion_tokens == 3
    assert resp.usage.total_tokens == 8
    assert resp.finish_reason == "stop"


def test_map_bedrock_response_concatenates_text_blocks() -> None:
    data = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "hello "}, {"text": "world"}],
            }
        },
        "usage": {"inputTokens": 0, "outputTokens": 0},
        "stopReason": "end_turn",
    }
    resp = map_bedrock_response("m", data)
    assert resp.text == "hello world"


def test_map_bedrock_response_finish_reason_mapping() -> None:
    base = {
        "output": {"message": {"role": "assistant", "content": [{"text": ""}]}},
        "usage": {"inputTokens": 0, "outputTokens": 0},
    }
    cases = {
        "end_turn": "stop",
        "max_tokens": "length",
        "tool_use": "tool_call",
        "guardrail_intervened": "content_filter",
        "weird": "stop",
    }
    for raw, expected in cases.items():
        data = {**base, "stopReason": raw}
        resp = map_bedrock_response("m", data)
        assert resp.finish_reason == expected, raw


def test_map_bedrock_response_missing_total_tokens_computed() -> None:
    data = {
        "output": {"message": {"role": "assistant", "content": [{"text": "x"}]}},
        "usage": {"inputTokens": 2, "outputTokens": 3},
        "stopReason": "end_turn",
    }
    resp = map_bedrock_response("m", data)
    assert resp.usage.total_tokens == 5


def test_map_bedrock_response_malformed_raises() -> None:
    with pytest.raises(LLMResponseFormatError):
        map_bedrock_response("m", {"unexpected": "shape"})


async def test_bedrock_client_complete_raises_not_implemented() -> None:
    client = BedrockClient(region="us-west-2")
    with pytest.raises(NotImplementedError, match="M9"):
        await client.complete(
            LLMRequest(
                messages=[LLMMessage(role="user", content="hi")],
                model="m",
            )
        )
    await client.aclose()


def test_bedrock_client_host_template() -> None:
    client = BedrockClient(region="ap-southeast-2")
    assert client.host() == "bedrock-runtime.ap-southeast-2.amazonaws.com"
