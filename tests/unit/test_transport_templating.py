"""Tests for request-body templating (render_body)."""

from __future__ import annotations

import json

import pytest

from agent_guardian.llm.errors import LLMPermanentError
from agent_guardian.transports.base import Message
from agent_guardian.transports.templating import json_escape, render_body


def test_render_simple_prompt() -> None:
    body = render_body('{"input": "{{ prompt }}"}', prompt="hello")
    assert body == {"input": "hello"}


def test_render_prompt_with_quotes_stays_json_safe() -> None:
    nasty = 'he said "hi"\nand left\tnow'
    body = render_body('{"input": "{{ prompt }}"}', prompt=nasty)
    assert body["input"] == nasty


def test_render_prompt_with_backslash() -> None:
    body = render_body('{"input": "{{ prompt }}"}', prompt="C:\\path\\x")
    assert body["input"] == "C:\\path\\x"


def test_render_session_escaped() -> None:
    body = render_body(
        '{"input": "{{ prompt }}", "session": "{{ session }}"}',
        prompt="p",
        session='s"1',
    )
    assert body["session"] == 's"1'


def test_render_session_none_becomes_empty_string() -> None:
    body = render_body(
        '{"input": "{{ prompt }}", "session": "{{ session }}"}',
        prompt="p",
        session=None,
    )
    assert body["session"] == ""


def test_render_conversation_inlines_history() -> None:
    convo = (
        Message(role="user", content="first"),
        Message(role="assistant", content='reply "q"'),
    )
    body = render_body(
        '{"messages": {{ conversation }}, "input": "{{ prompt }}"}',
        prompt="third",
        conversation=convo,
    )
    assert body["messages"] == [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": 'reply "q"'},
    ]
    assert body["input"] == "third"


def test_render_empty_conversation() -> None:
    body = render_body(
        '{"messages": {{ conversation }}}',
        prompt="x",
        conversation=(),
    )
    assert body["messages"] == []


def test_render_json_filter_for_extra() -> None:
    body = render_body(
        '{"meta": {{ meta | json }}, "input": "{{ prompt }}"}',
        prompt="p",
        extra={"meta": {"a": 1, "b": [1, 2]}},
    )
    assert body["meta"] == {"a": 1, "b": [1, 2]}


def test_render_invalid_template_raises_permanent() -> None:
    with pytest.raises(LLMPermanentError, match="template error"):
        render_body("{{ prompt", prompt="p")


def test_render_undefined_variable_raises_permanent() -> None:
    with pytest.raises(LLMPermanentError, match="template error"):
        render_body('{"x": "{{ does_not_exist }}"}', prompt="p")


def test_render_non_json_output_raises_permanent() -> None:
    with pytest.raises(LLMPermanentError, match="not valid JSON"):
        render_body("not json at all", prompt="p")


def test_render_non_object_output_raises_permanent() -> None:
    with pytest.raises(LLMPermanentError, match="must render to a JSON object"):
        render_body('["{{ prompt }}"]', prompt="p")


def test_json_escape_strips_quotes() -> None:
    escaped = json_escape('a"b')
    assert escaped == 'a\\"b'
    # round-trips inside a quoted context
    assert json.loads(f'"{escaped}"') == 'a"b'
