"""Tests for the six framework adapter construction / fingerprint surfaces.

The transport-layer happy/sad paths live in ``test_framework_production.py``;
this module covers the cheap construction, validation, and hook-registration
checks.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_guardian.adapters.framework import (
    ADKAdapter,
    AutoGenAdapter,
    CrewAIAdapter,
    FrameworkAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
    StrandsAdapter,
)


class _Graph:
    """Minimal LangGraph-like object."""

    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
        return {"messages": state["messages"] + [{"role": "assistant", "content": "x"}]}


class _Crew:
    """Minimal CrewAI-like object."""

    async def kickoff_async(self, *, inputs: dict[str, Any]) -> str:
        return "x"


class _Chat:
    """Minimal AutoGen-like object."""

    async def a_initiate_chat(self, *, message: str) -> str:
        del message
        return "x"


class _Agent:
    """Minimal OpenAI-Agents / Strands-like object."""

    async def run_async(self, *, input: str) -> str:
        del input
        return "x"

    async def invoke_async(self, prompt: str) -> str:
        del prompt
        return "x"


class _Runner:
    """Minimal ADK-like runner object."""

    async def run_async(self, *, input: str) -> str:
        del input
        return "x"


_ADAPTERS: list[tuple[type[FrameworkAdapter], Any, str, bool, bool, bool]] = [
    (ADKAdapter, _Runner(), "adk", False, True, True),
    (LangGraphAdapter, _Graph(), "langgraph", False, True, True),
    (StrandsAdapter, _Agent(), "strands", False, False, True),
    (OpenAIAgentsAdapter, _Agent(), "openai_agents", False, False, True),
    (AutoGenAdapter, _Chat(), "autogen", True, False, True),
    (CrewAIAdapter, _Crew(), "crewai", True, False, True),
]


@pytest.mark.parametrize(
    "cls,obj,framework,is_multi,has_memory,has_tools",
    _ADAPTERS,
)
def test_framework_stub_fingerprint(
    cls: type[FrameworkAdapter],
    obj: Any,
    framework: str,
    is_multi: bool,
    has_memory: bool,
    has_tools: bool,
) -> None:
    adapter = cls(obj)
    fp = adapter.fingerprint()
    assert fp.mode == "framework"
    assert fp.framework == framework
    assert fp.is_multi_agent is is_multi
    assert fp.has_memory is has_memory
    assert fp.has_tools is has_tools
    assert "Mode D" in fp.notes


@pytest.mark.parametrize(
    "cls,obj,framework,is_multi,has_memory,has_tools",
    _ADAPTERS,
)
def test_framework_stub_hook_registration(
    cls: type[FrameworkAdapter],
    obj: Any,
    framework: str,
    is_multi: bool,
    has_memory: bool,
    has_tools: bool,
) -> None:
    del framework, is_multi, has_memory, has_tools
    adapter = cls(obj)
    adapter.on_tool_call(lambda name, args: None)
    adapter.on_memory_write(lambda key, val: None)
    adapter.on_agent_message(lambda src, dst, content: None)
    assert len(adapter._tool_callbacks) == 1
    assert len(adapter._memory_callbacks) == 1
    assert len(adapter._message_callbacks) == 1


def test_framework_stub_default_ref_includes_object_type() -> None:
    adapter = ADKAdapter(_Runner())
    assert adapter.fingerprint().ref.startswith("adk:_Runner")


def test_framework_stub_custom_ref() -> None:
    adapter = LangGraphAdapter(_Graph(), ref="my-graph")
    assert adapter.fingerprint().ref == "my-graph"


def test_framework_base_is_abstract() -> None:
    with pytest.raises(TypeError):
        FrameworkAdapter()  # type: ignore[abstract]


def test_langgraph_rejects_none() -> None:
    with pytest.raises(ValueError, match="non-None"):
        LangGraphAdapter(None)


def test_langgraph_rejects_object_without_invoke() -> None:
    class _Bad:
        pass

    with pytest.raises(TypeError, match="ainvoke"):
        LangGraphAdapter(_Bad())


def test_crewai_rejects_object_without_kickoff() -> None:
    class _Bad:
        pass

    with pytest.raises(TypeError, match="kickoff"):
        CrewAIAdapter(_Bad())


def test_autogen_rejects_object_without_initiate() -> None:
    class _Bad:
        pass

    with pytest.raises(TypeError, match="initiate_chat"):
        AutoGenAdapter(_Bad())


def test_openai_agents_rejects_object_without_run() -> None:
    class _Bad:
        pass

    with pytest.raises(TypeError, match="run_async"):
        OpenAIAgentsAdapter(_Bad())


def test_strands_rejects_object_without_invoke() -> None:
    class _Bad:
        __slots__ = ()  # no __call__, no invoke

    bad = _Bad()
    # Strip __call__ off bound instance via a class that doesn't expose it.
    # The fallback default class still has __call__-of-type on the class but
    # not as a method — assert behaviour differently by handing in something
    # that fails the hasattr check.
    # We instead verify that handing in an empty dataclass fails — dicts
    # don't have invoke_async/invoke/__call__-as-method either, but they're
    # callable in the dunder sense, so use a richer guard.
    del bad  # placeholder for type-checker; real check below.

    class _Worse:
        pass

    with pytest.raises(TypeError, match="invoke"):
        StrandsAdapter(_Worse.__new__(_Worse))


def test_adk_rejects_object_without_run() -> None:
    class _Bad:
        pass

    with pytest.raises(TypeError, match="run"):
        ADKAdapter(_Bad.__new__(_Bad))
