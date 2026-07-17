"""Tests for Vertex request/response shaping (auth lands in M9)."""

from __future__ import annotations

import pytest

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import LLMResponseFormatError
from agent_guardian.llm.vertex import (
    VertexClient,
    build_vertex_payload,
    map_vertex_response,
)


def test_build_vertex_payload_simple() -> None:
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="gemini-1.5-pro",
    )
    payload = build_vertex_payload(req)
    assert payload["contents"] == [{"role": "user", "parts": [{"text": "hello"}]}]
    assert payload["generationConfig"]["maxOutputTokens"] == 1024
    assert payload["generationConfig"]["temperature"] == 0.7
    assert "systemInstruction" not in payload


def test_build_vertex_payload_maps_assistant_to_model() -> None:
    req = LLMRequest(
        messages=[
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content="hello back"),
            LLMMessage(role="user", content="more"),
        ],
        model="m",
    )
    payload = build_vertex_payload(req)
    roles = [c["role"] for c in payload["contents"]]
    assert roles == ["user", "model", "user"]


def test_build_vertex_payload_system_instruction() -> None:
    req = LLMRequest(
        messages=[
            LLMMessage(role="system", content="be terse"),
            LLMMessage(role="system", content="be polite"),
            LLMMessage(role="user", content="hi"),
        ],
        model="m",
    )
    payload = build_vertex_payload(req)
    assert payload["systemInstruction"] == {"parts": [{"text": "be terse\n\nbe polite"}]}


def test_build_vertex_payload_stop_sequences() -> None:
    req = LLMRequest(
        messages=[LLMMessage(role="user", content="hi")],
        model="m",
        stop=["X"],
    )
    payload = build_vertex_payload(req)
    assert payload["generationConfig"]["stopSequences"] == ["X"]


def test_map_vertex_response_happy_path() -> None:
    data = {
        "candidates": [
            {
                "content": {"role": "model", "parts": [{"text": "hi"}]},
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 4,
            "candidatesTokenCount": 1,
            "totalTokenCount": 5,
        },
    }
    resp = map_vertex_response("gemini-1.5", data)
    assert resp.text == "hi"
    assert resp.provider == "vertex"
    assert resp.usage.total_tokens == 5
    assert resp.finish_reason == "stop"


def test_map_vertex_response_includes_thinking_tokens() -> None:
    data = {
        "candidates": [{"content": {"parts": [{"text": "ok"}]}, "finishReason": "STOP"}],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 3,
            "thoughtsTokenCount": 17,
            "totalTokenCount": 30,
        },
    }
    usage = map_vertex_response("gemini-2.5-flash", data).usage
    assert usage.prompt_tokens == 10
    assert usage.completion_tokens == 20
    assert usage.total_tokens == 30


def test_map_vertex_response_uses_total_delta_when_thought_field_missing() -> None:
    data = {
        "candidates": [{"content": {"parts": [{"text": "ok"}]}, "finishReason": "STOP"}],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 3,
            "totalTokenCount": 25,
        },
    }
    assert map_vertex_response("gemini-2.5-flash", data).usage.completion_tokens == 15


def test_map_vertex_response_reconciles_inconsistent_total_upward() -> None:
    data = {
        "candidates": [{"content": {"parts": [{"text": "ok"}]}, "finishReason": "STOP"}],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 3,
            "thoughtsTokenCount": 17,
            "totalTokenCount": 12,
        },
    }
    usage = map_vertex_response("gemini-2.5-flash", data).usage
    assert usage.completion_tokens == 20
    assert usage.total_tokens == 30


def test_map_vertex_response_concatenates_parts() -> None:
    data = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": "hello "}, {"text": "world"}],
                },
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {"promptTokenCount": 0, "candidatesTokenCount": 0},
    }
    resp = map_vertex_response("m", data)
    assert resp.text == "hello world"


def test_map_vertex_response_finish_reason_mapping() -> None:
    base_candidate = {"content": {"role": "model", "parts": [{"text": ""}]}}
    cases = {
        "STOP": "stop",
        "MAX_TOKENS": "length",
        "SAFETY": "content_filter",
        "RECITATION": "content_filter",
        "OTHER": "stop",
        "MYSTERY": "stop",
    }
    for raw, expected in cases.items():
        data = {
            "candidates": [{**base_candidate, "finishReason": raw}],
            "usageMetadata": {"promptTokenCount": 0, "candidatesTokenCount": 0},
        }
        resp = map_vertex_response("m", data)
        assert resp.finish_reason == expected, raw


def test_map_vertex_response_malformed_raises() -> None:
    with pytest.raises(LLMResponseFormatError):
        map_vertex_response("m", {"unexpected": "shape"})


def test_vertex_client_host_template() -> None:
    client = VertexClient(project="p", region="europe-west4")
    assert client.host() == "europe-west4-aiplatform.googleapis.com"


def test_vertex_client_global_location_host() -> None:
    # ``global`` uses the region-less host with a ``locations/global`` path.
    client = VertexClient(project="p", location="global")
    assert client.host() == "aiplatform.googleapis.com"
