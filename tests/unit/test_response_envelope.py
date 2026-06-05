"""Response normalizer envelope (adapters/response_envelope.py)."""

from __future__ import annotations

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.adapters.http import HttpAdapterLastResponse
from agent_guardian.adapters.response_envelope import (
    EnvelopeToolCall,
    ResponseEnvelope,
    ResponseMapping,
    envelope_from_target,
    has_planted_token,
    project_http_last_response,
    project_json_response,
    project_text_response,
    tool_names_from_envelope,
)

# --------------------------------------------------------------------------
# ResponseMapping validation
# --------------------------------------------------------------------------


def test_mapping_rejects_path_without_dollar() -> None:
    with pytest.raises(ValueError, match="must start with"):
        ResponseMapping(text_path="output.text")


def test_mapping_allows_none_and_valid_paths() -> None:
    m = ResponseMapping(text_path="$.x", citations_path=None)
    assert m.text_path == "$.x"
    assert m.tool_name_path == "$.name"


# --------------------------------------------------------------------------
# project_text_response
# --------------------------------------------------------------------------


def test_project_text_response_basic() -> None:
    env = project_text_response("hello", latency_ms=12.5)
    assert env.text == "hello"
    assert env.format == "text"
    assert env.empty is False
    assert env.parse_success is True
    assert env.raw_body is None
    assert env.tool_calls == ()
    assert env.latency_ms == pytest.approx(12.5)


def test_project_text_response_empty() -> None:
    env = project_text_response("")
    assert env.empty is True
    assert env.format == "text"


# --------------------------------------------------------------------------
# project_json_response — autodetect + mapping
# --------------------------------------------------------------------------


def test_project_json_autodetect_openai_text() -> None:
    body = {"choices": [{"message": {"content": "hi there"}}]}
    env = project_json_response(body)
    assert env.text == "hi there"
    assert env.format == "json"
    assert env.parse_success is True
    assert env.empty is False


def test_project_json_autodetect_generic_text() -> None:
    env = project_json_response({"output": {"text": "result"}})
    assert env.text == "result"


def test_project_json_empty_body() -> None:
    env = project_json_response({"unrelated": 1})
    assert env.empty is True
    assert env.format == "empty"
    assert env.parse_success is False
    assert env.text == ""


def test_project_json_non_dict_body_is_unknown() -> None:
    env = project_json_response(["not", "a", "dict"])  # type: ignore[arg-type]
    assert env.format == "unknown"
    assert env.parse_success is False
    assert env.empty is True


def test_project_json_mapping_text_path() -> None:
    body = {"data": {"reply": "mapped"}}
    env = project_json_response(body, mapping=ResponseMapping(text_path="$.data.reply"))
    assert env.text == "mapped"


def test_project_json_autodetect_openai_tool_calls() -> None:
    body = {
        "choices": [
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {"name": "get_balance", "arguments": '{"acct": "123"}'},
                    ],
                }
            }
        ]
    }
    env = project_json_response(body)
    names = tool_names_from_envelope(env)
    assert names == ("get_balance",)
    # JSON-string args are decoded best-effort.
    assert env.tool_calls[0].arguments == {"acct": "123"}
    assert env.parse_success is True
    assert env.empty is False


def test_project_json_tool_args_bad_json_preserved_empty_with_warning() -> None:
    body = {"tool_calls": [{"name": "x", "arguments": "{not json"}]}
    env = project_json_response(body)
    assert env.tool_calls[0].name == "x"
    assert env.tool_calls[0].arguments == {}
    assert any("not JSON-decodable" in w for w in env.warnings)


def test_project_json_skips_blocks_without_name() -> None:
    body = {"content": [{"text": "just text"}, {"name": "do_thing", "input": {"a": 1}}]}
    env = project_json_response(body)
    names = tool_names_from_envelope(env)
    assert names == ("do_thing",)


def test_project_json_citations_via_mapping() -> None:
    body = {"text": "answer", "sources": ["a", "b", 3]}
    env = project_json_response(body, mapping=ResponseMapping(citations_path="$.sources"))
    assert env.citations == ("a", "b", "3")


def test_project_json_carries_transport_metadata() -> None:
    env = project_json_response(
        {"text": "ok"}, content_type="application/json", status_code=200, latency_ms=3.0
    )
    assert env.content_type == "application/json"
    assert env.status_code == 200
    assert env.latency_ms == pytest.approx(3.0)


# --------------------------------------------------------------------------
# project_http_last_response
# --------------------------------------------------------------------------


def test_project_http_last_response_adopts_tool_calls() -> None:
    from agent_guardian.adapters.http import HttpAdapterLastResponse, HttpAdapterToolCall

    snap = HttpAdapterLastResponse(
        text="done",
        tool_calls=(HttpAdapterToolCall(name="wire", arguments={"amt": 1}, raw={"x": 1}),),
        raw={"body": True},
    )
    env = project_http_last_response(snap, latency_ms=5.0)
    assert env.text == "done"
    assert env.format == "json"
    assert env.empty is False
    assert env.parse_success is True
    assert tool_names_from_envelope(env) == ("wire",)
    assert env.tool_calls[0].arguments == {"amt": 1}


def test_project_http_last_response_text_format_when_no_raw() -> None:
    from agent_guardian.adapters.http import HttpAdapterLastResponse

    snap = HttpAdapterLastResponse(text="plain", tool_calls=(), raw=None)
    env = project_http_last_response(snap)
    assert env.format == "text"
    assert env.empty is False


def test_project_http_last_response_empty() -> None:
    from agent_guardian.adapters.http import HttpAdapterLastResponse

    snap = HttpAdapterLastResponse(text="", tool_calls=(), raw=None)
    env = project_http_last_response(snap)
    assert env.empty is True


def test_project_http_citations_via_mapping() -> None:
    from agent_guardian.adapters.http import HttpAdapterLastResponse

    snap = HttpAdapterLastResponse(text="a", tool_calls=(), raw={"cites": ["s1", "s2"]})
    env = project_http_last_response(snap, mapping=ResponseMapping(citations_path="$.cites"))
    assert env.citations == ("s1", "s2")


def test_envelope_tool_call_from_http() -> None:
    from agent_guardian.adapters.http import HttpAdapterToolCall

    tc = HttpAdapterToolCall(name="t", arguments={"k": "v"}, raw={"orig": 1})
    env_tc = EnvelopeToolCall.from_http_tool_call(tc)
    assert env_tc.name == "t"
    assert env_tc.arguments == {"k": "v"}
    assert env_tc.raw == {"orig": 1}


# --------------------------------------------------------------------------
# envelope_from_target — lazy HttpAdapter isinstance + text fallback
# --------------------------------------------------------------------------


class _PlainTarget(TargetAdapter):
    mode = "code"

    def __init__(self) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="code", ref="plain")

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return "plain reply"


def test_envelope_from_target_non_http_uses_text() -> None:
    env = envelope_from_target(_PlainTarget(), "plain reply", latency_ms=2.0)
    assert env.format == "text"
    assert env.text == "plain reply"
    assert env.tool_calls == ()


def test_envelope_from_target_http_uses_snapshot() -> None:
    from agent_guardian.adapters.http import (
        HttpAdapter,
        HttpAdapterLastResponse,
        HttpAdapterToolCall,
    )

    adapter = HttpAdapter("https://x.example", shape="openai", model="gpt-4o-mini")
    adapter._last_response = HttpAdapterLastResponse(
        text="from-snapshot",
        tool_calls=(HttpAdapterToolCall(name="snap_tool", arguments={}),),
        raw={"ok": 1},
    )
    try:
        env = envelope_from_target(adapter, "ignored-text")
    finally:
        # adapter owns no live client work here; aclose is a no-op safety net.
        pass
    assert env.text == "from-snapshot"
    assert tool_names_from_envelope(env) == ("snap_tool",)


def test_envelope_from_target_http_without_snapshot_falls_back_to_text() -> None:
    from agent_guardian.adapters.http import HttpAdapter

    adapter = HttpAdapter("https://x.example", shape="openai", model="gpt-4o-mini")
    assert adapter._last_response is None
    env = envelope_from_target(adapter, "fallback text")
    assert env.format == "text"
    assert env.text == "fallback text"


# --------------------------------------------------------------------------
# is_error + to_dict
# --------------------------------------------------------------------------


def test_is_error_detects_sentinel() -> None:
    env = project_text_response("[target call failed: TimeoutError]")
    assert env.is_error is True
    assert project_text_response("ok").is_error is False


def test_to_dict_drops_none_optionals_and_includes_required() -> None:
    env = project_text_response("hi")
    d = env.to_dict()
    assert d["text"] == "hi"
    assert d["format"] == "text"
    assert d["is_error"] is False
    assert "tool_calls" in d
    # latency_ms / content_type / status_code were None -> dropped.
    assert "latency_ms" not in d
    assert "content_type" not in d
    assert "status_code" not in d
    # raw_body None -> dropped.
    assert "raw_body" not in d


def test_to_dict_serialises_tool_calls() -> None:
    body = {"tool_calls": [{"name": "f", "arguments": {"a": 1}}]}
    env = project_json_response(body)
    d = env.to_dict()
    assert d["tool_calls"] == [
        {"name": "f", "arguments": {"a": 1}, "raw": {"name": "f", "arguments": {"a": 1}}}
    ]


def test_to_dict_truncates_unserialisable_raw_body() -> None:
    class _NotJson:
        def __repr__(self) -> str:
            return "X" * 100

    env = ResponseEnvelope(
        text="t",
        format="json",
        empty=False,
        parse_success=True,
        raw_body={"obj": _NotJson()},
    )
    d = env.to_dict()
    assert "_truncated_repr" in d["raw_body"]
    assert any("truncated" in w for w in d["warnings"])


def test_to_dict_truncates_oversized_raw_body() -> None:
    big = {"blob": "z" * 20000}
    env = ResponseEnvelope(text="t", format="json", empty=False, parse_success=True, raw_body=big)
    d = env.to_dict()
    assert "_truncated_repr" in d["raw_body"]
    assert any("truncated" in w for w in d["warnings"])


# --------------------------------------------------------------------------
# has_planted_token — anchored regex
# --------------------------------------------------------------------------


def test_has_planted_token_exact_match() -> None:
    assert has_planted_token("The code was MEM-abc123.", "MEM-abc123") is True


def test_has_planted_token_word_boundary_trailing_punct() -> None:
    assert has_planted_token("It is MEM-abc123!", "MEM-abc123") is True


def test_has_planted_token_rejects_different_token() -> None:
    assert has_planted_token("The code was MEM-deadbe.", "MEM-abc123") is False


def test_has_planted_token_rejects_embedded_or_extended() -> None:
    assert has_planted_token("MEM-abc123456", "MEM-abc123") is False
    assert has_planted_token("xMEM-abc123", "MEM-abc123") is False


# --------------------------------------------------------------------------
# response_mapping override actually reaches the projector (regression).
# --------------------------------------------------------------------------


def _mis_extracted_snapshot() -> HttpAdapterLastResponse:
    """A real HttpAdapterLastResponse where the adapter auto-extracted the WRONG
    field; the real reply + cites live under a custom path in the raw body."""
    return HttpAdapterLastResponse(
        text="wrong-autodetected",
        tool_calls=(),
        raw={"data": {"reply": "the real text", "cites": ["a", "b"]}},
    )


def test_mapping_text_path_reprojects_http_snapshot_from_raw() -> None:
    # An explicit text_path means the operator wants the body re-read from a
    # known location — NOT the adapter's mis-extracted snapshot text.
    env = project_http_last_response(
        _mis_extracted_snapshot(), mapping=ResponseMapping(text_path="$.data.reply")
    )
    assert env.text == "the real text"


def test_mapping_citations_only_keeps_adapter_text() -> None:
    # A citations-only mapping must not disturb the adopted snapshot text.
    env = project_http_last_response(
        _mis_extracted_snapshot(), mapping=ResponseMapping(citations_path="$.data.cites")
    )
    assert env.text == "wrong-autodetected"
    assert env.citations == ("a", "b")


def test_envelope_from_target_threads_mapping_to_http_projector() -> None:
    # The full chain: envelope_from_target must forward the operator mapping
    # into the HTTP projector (the reviewer's HIGH "no-op mapping" regression).
    from agent_guardian.adapters.http import HttpAdapter

    adapter = HttpAdapter("https://x.example", shape="generic")
    adapter._last_response = HttpAdapterLastResponse(
        text="wrong-autodetected",
        tool_calls=(),
        raw={"data": {"reply": "the real text"}},
    )
    env = envelope_from_target(
        adapter, "ignored", mapping=ResponseMapping(text_path="$.data.reply")
    )
    assert env.text == "the real text"
