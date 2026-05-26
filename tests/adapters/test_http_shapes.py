"""Pure-function tests for HTTP shape request builders and extractors."""

from __future__ import annotations

import pytest

from agent_guardian.adapters.http_shapes import get_shape, list_shapes
from agent_guardian.adapters.http_shapes.agentcore_shape import (
    build_request as agentcore_build,
)
from agent_guardian.adapters.http_shapes.agentcore_shape import (
    extract_response_text as agentcore_extract,
)
from agent_guardian.adapters.http_shapes.anthropic_shape import (
    build_request as anth_build,
)
from agent_guardian.adapters.http_shapes.anthropic_shape import (
    extract_response_text as anth_extract,
)
from agent_guardian.adapters.http_shapes.base import HttpShape, register_shape
from agent_guardian.adapters.http_shapes.bedrock_shape import (
    build_request as bedrock_build,
)
from agent_guardian.adapters.http_shapes.bedrock_shape import (
    extract_response_text as bedrock_extract,
)
from agent_guardian.adapters.http_shapes.generic_shape import (
    build_request as generic_build,
)
from agent_guardian.adapters.http_shapes.generic_shape import (
    extract_response_text as generic_extract,
)
from agent_guardian.adapters.http_shapes.generic_shape import (
    walk_jsonpath,
)
from agent_guardian.adapters.http_shapes.openai_shape import (
    build_request as oai_build,
)
from agent_guardian.adapters.http_shapes.openai_shape import (
    extract_response_text as oai_extract,
)
from agent_guardian.adapters.http_shapes.vertex_shape import (
    build_request as vertex_build,
)
from agent_guardian.adapters.http_shapes.vertex_shape import (
    extract_response_text as vertex_extract,
)

# ---- registry --------------------------------------------------------------


def test_list_shapes_includes_all_builtins() -> None:
    names = list_shapes()
    for expected in ("openai", "anthropic", "bedrock", "vertex", "agentcore", "generic"):
        assert expected in names


def test_get_shape_returns_httpshape_instance() -> None:
    shape = get_shape("openai")
    assert isinstance(shape, HttpShape)
    assert shape.name == "openai"
    assert shape.auth_header_format == "Bearer {key}"


def test_get_shape_unknown_raises() -> None:
    with pytest.raises(KeyError):
        get_shape("nope")


def test_register_shape_duplicate_raises() -> None:
    with pytest.raises(ValueError):
        register_shape(get_shape("openai"))


# ---- openai ----------------------------------------------------------------


def test_openai_build_request() -> None:
    body = oai_build("hello", model="gpt-4o-mini")
    assert body["model"] == "gpt-4o-mini"
    assert body["messages"][0]["content"] == "hello"
    assert body["messages"][0]["role"] == "user"


def test_openai_build_request_with_session_and_extra() -> None:
    body = oai_build("hi", session="user-42", extra={"temperature": 0.1})
    assert body["user"] == "user-42"
    assert body["temperature"] == 0.1


def test_openai_extract_response_text() -> None:
    payload = {"choices": [{"message": {"content": "the reply"}}]}
    assert oai_extract(payload) == "the reply"


def test_openai_extract_response_text_malformed() -> None:
    with pytest.raises(ValueError):
        oai_extract({"choices": []})


# ---- anthropic -------------------------------------------------------------


def test_anthropic_build_request() -> None:
    body = anth_build("hello")
    assert body["model"] == "claude-3-5-sonnet-latest"
    assert body["max_tokens"] == 1024
    assert body["messages"][0]["content"] == "hello"


def test_anthropic_build_request_session_becomes_metadata() -> None:
    body = anth_build("hi", session="u-1")
    assert body["metadata"] == {"user_id": "u-1"}


def test_anthropic_build_request_extra_merges() -> None:
    body = anth_build("hi", extra={"system": "be brief"})
    assert body["system"] == "be brief"


def test_anthropic_extract_response_text() -> None:
    payload = {
        "content": [
            {"type": "text", "text": "Hello"},
            {"type": "text", "text": " world"},
        ]
    }
    assert anth_extract(payload) == "Hello world"


def test_anthropic_extract_response_text_malformed() -> None:
    with pytest.raises(ValueError):
        anth_extract({"wrong": "shape"})


# ---- bedrock ---------------------------------------------------------------


def test_bedrock_build_request() -> None:
    body = bedrock_build("hi", model="anthropic.claude-3-haiku-20240307-v1:0")
    assert body["modelId"] == "anthropic.claude-3-haiku-20240307-v1:0"
    assert body["messages"][0]["content"][0]["text"] == "hi"
    assert body["inferenceConfig"]["maxTokens"] == 1024


def test_bedrock_build_request_session_in_additional_fields() -> None:
    body = bedrock_build("hi", session="abc")
    assert body["additionalModelRequestFields"] == {"session_id": "abc"}


def test_bedrock_build_request_extra_merges() -> None:
    body = bedrock_build("hi", extra={"toolConfig": {"tools": []}})
    assert body["toolConfig"] == {"tools": []}


def test_bedrock_extract_response_text() -> None:
    payload = {
        "output": {
            "message": {"content": [{"text": "out"}]},
        }
    }
    assert bedrock_extract(payload) == "out"


def test_bedrock_extract_response_text_malformed() -> None:
    with pytest.raises(ValueError):
        bedrock_extract({})


# ---- vertex ----------------------------------------------------------------


def test_vertex_build_request() -> None:
    body = vertex_build("hi", model="gemini-1.5-pro")
    assert body["model"] == "gemini-1.5-pro"
    assert body["contents"][0]["parts"][0]["text"] == "hi"


def test_vertex_build_request_session_label() -> None:
    body = vertex_build("hi", session="abc")
    assert body["labels"] == {"session": "abc"}


def test_vertex_build_request_extra_merges() -> None:
    body = vertex_build("hi", extra={"safetySettings": [{"category": "X"}]})
    assert body["safetySettings"] == [{"category": "X"}]


def test_vertex_extract_response_text() -> None:
    payload = {
        "candidates": [
            {"content": {"parts": [{"text": "out"}]}},
        ]
    }
    assert vertex_extract(payload) == "out"


def test_vertex_extract_response_text_malformed() -> None:
    with pytest.raises(ValueError):
        vertex_extract({"candidates": []})


# ---- agentcore -------------------------------------------------------------


def test_agentcore_build_request() -> None:
    body = agentcore_build("hi", model="model-id", session="sess")
    assert body["input"]["prompt"] == "hi"
    assert body["modelId"] == "model-id"
    assert body["sessionId"] == "sess"


def test_agentcore_build_request_extra_merges() -> None:
    body = agentcore_build("hi", extra={"agentId": "a-1"})
    assert body["agentId"] == "a-1"


def test_agentcore_extract_from_output_text() -> None:
    assert agentcore_extract({"output": {"text": "ok"}}) == "ok"


def test_agentcore_extract_from_output_message() -> None:
    assert agentcore_extract({"output": {"message": "msg"}}) == "msg"


def test_agentcore_extract_from_completion() -> None:
    assert agentcore_extract({"completion": "done"}) == "done"


def test_agentcore_extract_skips_non_dict_output() -> None:
    # ``output`` is a string, not a dict → fall through to ``completion``.
    assert agentcore_extract({"output": "ignored", "completion": "yes"}) == "yes"


def test_agentcore_extract_malformed_raises() -> None:
    with pytest.raises(ValueError):
        agentcore_extract({})


# ---- generic ---------------------------------------------------------------


def test_generic_build_request() -> None:
    body = generic_build("hi", session="s")
    assert body == {"input": "hi", "session": "s"}


def test_generic_build_request_extra_merges() -> None:
    body = generic_build("hi", extra={"top": 1})
    assert body["top"] == 1


def test_generic_build_request_model_param() -> None:
    body = generic_build("hi", model="m-1")
    assert body["model"] == "m-1"


def test_generic_extract_default_path() -> None:
    payload = {"output": {"text": "answer"}}
    assert generic_extract(payload) == "answer"


def test_generic_extract_custom_path() -> None:
    payload = {"data": {"messages": [{"content": "first"}, {"content": "second"}]}}
    assert generic_extract(payload, jsonpath="$.data.messages[1].content") == "second"


def test_generic_extract_missing_path_raises() -> None:
    with pytest.raises(ValueError):
        generic_extract({"output": {}})


# ---- jsonpath subset -------------------------------------------------------


def test_walk_jsonpath_root() -> None:
    assert walk_jsonpath({"a": 1}, "$") == {"a": 1}


def test_walk_jsonpath_nested() -> None:
    assert walk_jsonpath({"a": {"b": {"c": 7}}}, "$.a.b.c") == 7


def test_walk_jsonpath_array_index() -> None:
    assert walk_jsonpath({"xs": ["x", "y", "z"]}, "$.xs[1]") == "y"


def test_walk_jsonpath_negative_index() -> None:
    assert walk_jsonpath({"xs": ["x", "y", "z"]}, "$.xs[-1]") == "z"


def test_walk_jsonpath_missing_key_returns_none() -> None:
    assert walk_jsonpath({"a": 1}, "$.b") is None


def test_walk_jsonpath_index_out_of_range_returns_none() -> None:
    assert walk_jsonpath({"xs": [1]}, "$.xs[5]") is None


def test_walk_jsonpath_index_on_non_list_returns_none() -> None:
    assert walk_jsonpath({"xs": {"k": 1}}, "$.xs[0]") is None


def test_walk_jsonpath_unexpected_token_raises() -> None:
    with pytest.raises(ValueError, match="unexpected"):
        walk_jsonpath({"a": 1}, "$a")


def test_walk_jsonpath_must_start_with_dollar() -> None:
    with pytest.raises(ValueError):
        walk_jsonpath({}, "a.b")


def test_walk_jsonpath_bad_index_raises() -> None:
    with pytest.raises(ValueError):
        walk_jsonpath({"xs": [1]}, "$.xs[abc]")


def test_walk_jsonpath_unterminated_bracket_raises() -> None:
    with pytest.raises(ValueError):
        walk_jsonpath({"xs": [1]}, "$.xs[0")


def test_walk_jsonpath_empty_key_raises() -> None:
    with pytest.raises(ValueError):
        walk_jsonpath({"a": 1}, "$..a")


def test_walk_jsonpath_traverse_non_dict_returns_none() -> None:
    assert walk_jsonpath({"a": 1}, "$.a.b") is None
