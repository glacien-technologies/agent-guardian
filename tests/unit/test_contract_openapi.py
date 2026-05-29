"""Unit tests for the OpenAPI 3.1 -> contract-shape generator (Stage 4)."""

from __future__ import annotations

from typing import Any

import pytest

from agent_guardian.contract.openapi import (
    OperationCandidate,
    generate_http_shapes,
    list_operations,
)

# ---------------------------------------------------------------------------
# Fixtures / spec builders
# ---------------------------------------------------------------------------


def _simple_spec() -> dict[str, Any]:
    """A /chat POST taking {input: string} and returning {output: {text: string}}."""
    return {
        "openapi": "3.1.0",
        "info": {"title": "Chat", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/chat": {
                "post": {
                    "summary": "Chat with the bot",
                    "operationId": "chat",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"input": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "output": {
                                                "type": "object",
                                                "properties": {"text": {"type": "string"}},
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            }
        },
    }


def _ref_spec() -> dict[str, Any]:
    """Same shape as the simple spec but via $ref into components/schemas."""
    return {
        "openapi": "3.1.0",
        "info": {"title": "Chat", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com/v1/"}],
        "paths": {
            "/chat": {
                "post": {
                    "requestBody": {
                        "$ref": "#/components/requestBodies/ChatBody",
                    },
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ChatReply"}
                                }
                            },
                        }
                    },
                }
            }
        },
        "components": {
            "requestBodies": {
                "ChatBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/ChatRequest"}}
                    }
                }
            },
            "schemas": {
                "ChatRequest": {
                    "type": "object",
                    "properties": {"prompt": {"$ref": "#/components/schemas/PromptString"}},
                },
                "PromptString": {"type": "string"},
                "ChatReply": {
                    "type": "object",
                    "properties": {"answer": {"type": "string"}},
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Core generation: the simple /chat spec
# ---------------------------------------------------------------------------


def test_generate_simple_spec_url_method_body_and_output_path() -> None:
    shapes = generate_http_shapes(_simple_spec())

    assert shapes["transport"] == {
        "kind": "http",
        "url": "https://api.example.com/v1/chat",
        "method": "POST",
    }
    assert shapes["request"]["content_type"] == "application/json"
    # The prompt is mapped to the request's only string field, "input".
    assert shapes["request"]["body"] == '{"input": "{{ prompt }}"}'
    # The most-likely text field of the 200 response is output.text.
    assert shapes["response"]["output_path"] == "$.output.text"


def test_generate_body_template_references_prompt() -> None:
    shapes = generate_http_shapes(_simple_spec())
    assert "{{ prompt }}" in shapes["request"]["body"]


def test_explicit_path_and_method_selection() -> None:
    shapes = generate_http_shapes(_simple_spec(), path="/chat", method="post")
    assert shapes["transport"]["url"] == "https://api.example.com/v1/chat"


# ---------------------------------------------------------------------------
# $ref resolution
# ---------------------------------------------------------------------------


def test_ref_resolution_request_and_response() -> None:
    shapes = generate_http_shapes(_ref_spec())
    # trailing slash on server url is collapsed
    assert shapes["transport"]["url"] == "https://api.example.com/v1/chat"
    # request schema reached through requestBody -> schema -> property $ref chain
    assert shapes["request"]["body"] == '{"prompt": "{{ prompt }}"}'
    # response schema reached through a $ref
    assert shapes["response"]["output_path"] == "$.answer"


def test_unresolvable_ref_raises() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["requestBody"] = {"$ref": "#/components/nope/Missing"}
    with pytest.raises(ValueError, match="does not resolve"):
        generate_http_shapes(spec)


def test_remote_ref_unsupported() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["requestBody"] = {"$ref": "https://example.com/schema.json#/Foo"}
    with pytest.raises(ValueError, match=r"local '#/\.\.\.' references"):
        generate_http_shapes(spec)


def test_recursive_ref_is_stopped() -> None:
    spec = _simple_spec()
    spec["components"] = {"schemas": {"Loop": {"$ref": "#/components/schemas/Loop"}}}
    spec["paths"]["/chat"]["post"]["requestBody"] = {
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Loop"}}}
    }
    with pytest.raises(ValueError, match="too deep"):
        generate_http_shapes(spec)


# ---------------------------------------------------------------------------
# Field-selection heuristics
# ---------------------------------------------------------------------------


def test_hinted_field_wins_over_first_string_property() -> None:
    spec = _simple_spec()
    # Two string fields: "metadata" (first, no hint) and "prompt" (hinted).
    spec["paths"]["/chat"]["post"]["requestBody"]["content"]["application/json"]["schema"][
        "properties"
    ] = {
        "metadata": {"type": "string"},
        "prompt": {"type": "string"},
    }
    shapes = generate_http_shapes(spec)
    assert shapes["request"]["body"] == '{"prompt": "{{ prompt }}"}'


def test_first_string_property_when_no_hint_matches() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["requestBody"]["content"]["application/json"]["schema"][
        "properties"
    ] = {
        "alpha": {"type": "string"},
        "beta": {"type": "string"},
    }
    shapes = generate_http_shapes(spec)
    assert shapes["request"]["body"] == '{"alpha": "{{ prompt }}"}'


def test_nullable_string_type_list_is_recognised() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["requestBody"]["content"]["application/json"]["schema"][
        "properties"
    ] = {"input": {"type": ["string", "null"]}}
    shapes = generate_http_shapes(spec)
    assert shapes["request"]["body"] == '{"input": "{{ prompt }}"}'


def test_hint_priority_prompt_beats_message() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["requestBody"]["content"]["application/json"]["schema"][
        "properties"
    ] = {
        "message": {"type": "string"},
        "prompt": {"type": "string"},
    }
    shapes = generate_http_shapes(spec)
    # "prompt" ranks before "message" in the hint list.
    assert shapes["request"]["body"] == '{"prompt": "{{ prompt }}"}'


def test_allof_composition_exposes_properties() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["requestBody"]["content"]["application/json"]["schema"] = {
        "allOf": [
            {"type": "object", "properties": {"meta": {"type": "integer"}}},
            {"type": "object", "properties": {"query": {"type": "string"}}},
        ]
    }
    shapes = generate_http_shapes(spec)
    assert shapes["request"]["body"] == '{"query": "{{ prompt }}"}'


def test_no_string_field_falls_back_to_top_level_prompt() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["requestBody"]["content"]["application/json"]["schema"][
        "properties"
    ] = {"count": {"type": "integer"}}
    shapes = generate_http_shapes(spec)
    assert shapes["request"]["body"] == "{{ prompt }}"


def test_no_response_text_field_defaults_output_path_to_root() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "type": "object",
        "properties": {"code": {"type": "integer"}},
    }
    shapes = generate_http_shapes(spec)
    assert shapes["response"]["output_path"] == "$"


def test_no_json_response_defaults_output_path_to_root() -> None:
    spec = _simple_spec()
    spec["paths"]["/chat"]["post"]["responses"] = {"204": {"description": "no content"}}
    shapes = generate_http_shapes(spec)
    assert shapes["response"]["output_path"] == "$"


# ---------------------------------------------------------------------------
# Heuristic operation selection (no explicit path)
# ---------------------------------------------------------------------------


def test_heuristic_picks_first_post_with_json_body() -> None:
    spec = _simple_spec()
    # A GET that comes first in document order should be skipped in favour of
    # the body-bearing POST.
    spec["paths"] = {
        "/health": {"get": {"responses": {"200": {"description": "ok"}}}},
        **spec["paths"],
    }
    shapes = generate_http_shapes(spec)
    assert shapes["transport"]["method"] == "POST"
    assert shapes["transport"]["url"].endswith("/chat")


def test_heuristic_prefers_post_over_put_in_method_order() -> None:
    spec = _simple_spec()
    body = spec["paths"]["/chat"]["post"]["requestBody"]
    spec["paths"] = {
        "/put-first": {
            "put": {
                "requestBody": body,
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/chat": spec["paths"]["/chat"],
    }
    shapes = generate_http_shapes(spec)
    # POST is preferred over PUT regardless of document order.
    assert shapes["transport"]["method"] == "POST"
    assert shapes["transport"]["url"].endswith("/chat")


def test_vendor_json_media_type_is_recognised() -> None:
    spec = _simple_spec()
    op = spec["paths"]["/chat"]["post"]
    op["requestBody"] = {
        "content": {
            "application/vnd.acme+json": {
                "schema": {"type": "object", "properties": {"input": {"type": "string"}}}
            }
        }
    }
    shapes = generate_http_shapes(spec)
    assert shapes["request"]["content_type"] == "application/vnd.acme+json"
    assert shapes["request"]["body"] == '{"input": "{{ prompt }}"}'


# ---------------------------------------------------------------------------
# Operation listing
# ---------------------------------------------------------------------------


def test_list_operations_reports_candidates() -> None:
    spec = _simple_spec()
    spec["paths"]["/health"] = {"get": {"responses": {"200": {"description": "ok"}}}}
    ops = list_operations(spec)
    by_key = {(o.method, o.path): o for o in ops}
    assert ("post", "/chat") in by_key
    assert ("get", "/health") in by_key
    assert by_key[("post", "/chat")].has_json_body is True
    assert by_key[("post", "/chat")].operation_id == "chat"
    assert by_key[("post", "/chat")].summary == "Chat with the bot"
    assert by_key[("get", "/health")].has_json_body is False


def test_operation_candidate_equality_and_slots() -> None:
    a = OperationCandidate(
        path="/x",
        method="post",
        operation={},
        has_json_body=True,
        operation_id="x",
        summary=None,
    )
    b = OperationCandidate(
        path="/x",
        method="post",
        operation={"different": True},
        has_json_body=True,
        operation_id="x",
        summary=None,
    )
    assert a == b
    assert a != object()
    with pytest.raises(AttributeError):
        a.unknown_attr = 1  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Error / robustness paths
# ---------------------------------------------------------------------------


def test_no_suitable_operation_raises() -> None:
    spec = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    with pytest.raises(ValueError, match="no operation with a JSON request body"):
        generate_http_shapes(spec)


def test_missing_servers_raises() -> None:
    spec = _simple_spec()
    del spec["servers"]
    with pytest.raises(ValueError, match="no 'servers'"):
        generate_http_shapes(spec)


def test_servers_entry_not_object_raises() -> None:
    spec = _simple_spec()
    spec["servers"] = ["https://api.example.com"]
    with pytest.raises(ValueError, match=r"servers\[0\]' is not an object"):
        generate_http_shapes(spec)


def test_server_url_missing_raises() -> None:
    spec = _simple_spec()
    spec["servers"] = [{"description": "no url here"}]
    with pytest.raises(ValueError, match=r"servers\[0\]\.url"):
        generate_http_shapes(spec)


def test_missing_paths_raises() -> None:
    spec = {"openapi": "3.1.0", "servers": [{"url": "https://x.example"}]}
    with pytest.raises(ValueError, match="no 'paths'"):
        generate_http_shapes(spec)


def test_empty_spec_raises() -> None:
    with pytest.raises(ValueError, match="empty or not a mapping"):
        generate_http_shapes({})


def test_explicit_path_not_found_raises() -> None:
    with pytest.raises(ValueError, match="no POST operation at path '/missing'"):
        generate_http_shapes(_simple_spec(), path="/missing", method="post")


def test_explicit_method_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="no PUT operation at path '/chat'"):
        generate_http_shapes(_simple_spec(), path="/chat", method="put")


def test_operation_without_json_body_via_explicit_path_raises() -> None:
    spec = _simple_spec()
    spec["paths"]["/ping"] = {"get": {"responses": {"200": {"description": "ok"}}}}
    with pytest.raises(ValueError, match="has no JSON request"):
        generate_http_shapes(spec, path="/ping", method="get")


def test_list_operations_skips_non_object_path_items() -> None:
    spec = _simple_spec()
    spec["paths"]["/weird"] = "not-a-path-item"
    ops = list_operations(spec)
    assert all(o.path != "/weird" for o in ops)


def test_heuristic_falls_back_to_any_json_body_method() -> None:
    # Only a GET carries a JSON body — no preferred (POST/PUT/PATCH) verb does.
    spec = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/search": {
                "get": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"query": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"text": {"type": "string"}},
                                    }
                                }
                            },
                        }
                    },
                }
            }
        },
    }
    shapes = generate_http_shapes(spec)
    assert shapes["transport"]["method"] == "GET"
    assert shapes["request"]["body"] == '{"query": "{{ prompt }}"}'
    assert shapes["response"]["output_path"] == "$.text"


def test_ref_to_non_object_node_raises() -> None:
    spec = _simple_spec()
    spec["components"] = {"schemas": {"NotAnObject": ["a", "list"]}}
    spec["paths"]["/chat"]["post"]["requestBody"] = {
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/NotAnObject"}}}
    }
    with pytest.raises(ValueError, match="non-object node"):
        generate_http_shapes(spec)


def test_path_without_leading_slash_is_joined_cleanly() -> None:
    spec = _simple_spec()
    # Swap the path for one lacking a leading slash; the join still inserts one.
    spec["paths"] = {"chat": spec["paths"]["/chat"]}
    shapes = generate_http_shapes(spec)
    assert shapes["transport"]["url"] == "https://api.example.com/v1/chat"


def test_non_dict_media_schema_is_ignored_for_body() -> None:
    spec = _simple_spec()
    # A JSON media type whose schema is missing -> treated as no JSON body.
    spec["paths"]["/chat"]["post"]["requestBody"] = {
        "content": {"application/json": {"example": {"input": "hi"}}}
    }
    with pytest.raises(ValueError, match="no operation with a JSON request body"):
        generate_http_shapes(spec)
