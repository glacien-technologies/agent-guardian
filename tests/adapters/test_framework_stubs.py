"""Tests for the six framework adapter stubs."""

from __future__ import annotations

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


class _Sentinel:
    """Stand-in framework-native object."""


_ADAPTERS = [
    (ADKAdapter, "adk", False, True, True),
    (LangGraphAdapter, "langgraph", False, True, True),
    (StrandsAdapter, "strands", False, False, True),
    (OpenAIAgentsAdapter, "openai_agents", False, False, True),
    (AutoGenAdapter, "autogen", True, False, True),
    (CrewAIAdapter, "crewai", True, False, True),
]


@pytest.mark.parametrize(
    "cls,framework,is_multi,has_memory,has_tools",
    _ADAPTERS,
)
def test_framework_stub_fingerprint(
    cls: type[FrameworkAdapter],
    framework: str,
    is_multi: bool,
    has_memory: bool,
    has_tools: bool,
) -> None:
    adapter = cls(_Sentinel())
    fp = adapter.fingerprint()
    assert fp.mode == "framework"
    assert fp.framework == framework
    assert fp.is_multi_agent is is_multi
    assert fp.has_memory is has_memory
    assert fp.has_tools is has_tools
    assert "M9" in fp.notes


@pytest.mark.parametrize(
    "cls,framework,is_multi,has_memory,has_tools",
    _ADAPTERS,
)
async def test_framework_stub_call_raises(
    cls: type[FrameworkAdapter],
    framework: str,
    is_multi: bool,
    has_memory: bool,
    has_tools: bool,
) -> None:
    del framework, is_multi, has_memory, has_tools
    adapter = cls(_Sentinel())
    with pytest.raises(NotImplementedError, match="M9"):
        await adapter.call("hi")


@pytest.mark.parametrize(
    "cls,framework,is_multi,has_memory,has_tools",
    _ADAPTERS,
)
def test_framework_stub_hook_registration(
    cls: type[FrameworkAdapter],
    framework: str,
    is_multi: bool,
    has_memory: bool,
    has_tools: bool,
) -> None:
    del framework, is_multi, has_memory, has_tools
    adapter = cls(_Sentinel())
    adapter.on_tool_call(lambda name, args: None)
    adapter.on_memory_write(lambda key, val: None)
    adapter.on_agent_message(lambda src, dst, content: None)
    # Hooks land in the internal lists.
    assert len(adapter._tool_callbacks) == 1
    assert len(adapter._memory_callbacks) == 1
    assert len(adapter._message_callbacks) == 1


def test_framework_stub_default_ref_includes_object_type() -> None:
    adapter = ADKAdapter(_Sentinel())
    assert adapter.fingerprint().ref.startswith("adk:_Sentinel")


def test_framework_stub_custom_ref() -> None:
    adapter = LangGraphAdapter(_Sentinel(), ref="my-graph")
    assert adapter.fingerprint().ref == "my-graph"


def test_framework_base_is_abstract() -> None:
    with pytest.raises(TypeError):
        FrameworkAdapter()  # type: ignore[abstract]
