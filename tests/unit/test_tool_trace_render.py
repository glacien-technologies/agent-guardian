"""_render_tool_trace must surface tool-call ARGUMENTS to the judge, not only
names.

The judge rubric asks for "unsafe arguments / exfiltration endpoints", and the
envelope already decodes ``EnvelopeToolCall.arguments`` — but the rendered trace
historically passed only ``tc.name``, dropping the very evidence the judge needs
(the amount wired, the destination account, the URL exfiltrated to). This pins
that the arguments now reach the trace, bounded and JSON-rendered, while the
black-box fallback is preserved.
"""

from __future__ import annotations

import types
from typing import Any

import pytest

from agent_guardian.adapters.response_envelope import EnvelopeToolCall
from agent_guardian.agents import base


def _env(*calls: EnvelopeToolCall) -> Any:
    return types.SimpleNamespace(tool_calls=tuple(calls))


def test_trace_includes_argument_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        base,
        "envelope_from_target",
        lambda *a, **k: _env(
            EnvelopeToolCall(name="wire_transfer", arguments={"amount": 9500, "to": "acct-999"}),
            EnvelopeToolCall(name="lookup_balance", arguments={}),
        ),
    )
    trace = base._render_tool_trace(object(), "resp")
    # The tool names are still present...
    assert "wire_transfer" in trace
    assert "lookup_balance" in trace
    # ...and now the ARGUMENT VALUES the judge needs are too.
    assert "9500" in trace
    assert "acct-999" in trace


def test_trace_black_box_fallback_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "envelope_from_target", lambda *a, **k: _env())
    assert base._render_tool_trace(object(), "resp") == "(none — black-box target)"


def test_trace_projection_error_degrades_to_black_box(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("projection failed")

    monkeypatch.setattr(base, "envelope_from_target", _boom)
    assert base._render_tool_trace(object(), "resp") == "(none — black-box target)"


def test_trace_caps_oversized_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    big = {"blob": "x" * 5000}
    monkeypatch.setattr(
        base,
        "envelope_from_target",
        lambda *a, **k: _env(EnvelopeToolCall(name="dump", arguments=big)),
    )
    trace = base._render_tool_trace(object(), "resp")
    assert "dump" in trace
    # The rendered trace is bounded — it must not splat a 5k-char argument blob
    # verbatim into the judge prompt.
    assert len(trace) < 1000
