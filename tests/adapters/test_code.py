"""Tests for CodeAdapter (Mode B)."""

from __future__ import annotations

import warnings

import pytest

from agent_guardian.adapters.code import CodeAdapter
from tests.adapters._fixtures import sample_agent, sample_class_agent


async def test_async_function_target() -> None:
    adapter = CodeAdapter(sample_agent.async_agent)
    assert await adapter.call("hi") == "async:hi"


async def test_sync_function_target() -> None:
    adapter = CodeAdapter(sample_agent.sync_agent)
    assert await adapter.call("hi") == "sync:hi"


async def test_async_function_with_session() -> None:
    adapter = CodeAdapter(sample_agent.async_with_session)
    out = await adapter.call("hi", session="sess-1")
    assert out == "async:hi:sess-1"


async def test_sync_function_with_session() -> None:
    adapter = CodeAdapter(sample_agent.sync_with_session)
    out = await adapter.call("hi", session="sess-2")
    assert out == "sync:hi:sess-2"


async def test_callable_instance_target() -> None:
    adapter = CodeAdapter(sample_class_agent.CallableAgent())
    out = await adapter.call("hi", session="s")
    assert out == "call:hi:s"


async def test_async_callable_instance_target() -> None:
    adapter = CodeAdapter(sample_class_agent.AsyncCallableAgent())
    assert await adapter.call("hi") == "acall:hi"


async def test_class_target_is_instantiated() -> None:
    adapter = CodeAdapter(sample_class_agent.CallableAgent)
    out = await adapter.call("hi", session="s")
    assert out == "call:hi:s"


async def test_class_without_default_constructor_raises() -> None:
    class NeedsArg:
        def __init__(self, x: int) -> None:
            self.x = x

        def __call__(self, prompt: str) -> str:
            return prompt

    with pytest.raises(TypeError):
        CodeAdapter(NeedsArg)


async def test_method_via_dotted_path() -> None:
    adapter = CodeAdapter("tests.adapters._fixtures.sample_class_agent:AgentWithKickoff.kickoff")
    out = await adapter.call("hi")
    assert out == "kickoff:hi"


async def test_dotted_path_function() -> None:
    adapter = CodeAdapter("tests.adapters._fixtures.sample_agent:async_agent")
    assert await adapter.call("hi") == "async:hi"


async def test_dotted_path_class_instantiated() -> None:
    adapter = CodeAdapter("tests.adapters._fixtures.sample_class_agent:CallableAgent")
    assert await adapter.call("hi", session="s") == "call:hi:s"


async def test_from_dotted_path_classmethod() -> None:
    adapter = CodeAdapter.from_dotted_path("tests.adapters._fixtures.sample_agent:async_agent")
    assert await adapter.call("hi") == "async:hi"


def test_dotted_path_missing_colon_raises() -> None:
    with pytest.raises(ValueError, match=":"):
        CodeAdapter("tests.adapters._fixtures.sample_agent.async_agent")


def test_dotted_path_empty_segments_raise() -> None:
    with pytest.raises(ValueError):
        CodeAdapter(":foo")
    with pytest.raises(ValueError):
        CodeAdapter("mod:")


def test_dotted_path_non_callable_raises() -> None:
    with pytest.raises(TypeError):
        CodeAdapter("tests.adapters._fixtures.sample_agent:tools")


def test_non_callable_target_raises() -> None:
    with pytest.raises(TypeError):
        CodeAdapter(42)  # type: ignore[arg-type]


async def test_fingerprint_detects_tools_from_callable_attr() -> None:
    adapter = CodeAdapter(sample_agent.sync_agent)
    fp = adapter.fingerprint()
    assert fp.mode == "code"
    assert fp.has_tools is True
    assert "search" in fp.declared_tools


async def test_fingerprint_detects_multi_agent_from_class() -> None:
    adapter = CodeAdapter(sample_class_agent.CallableAgent())
    fp = adapter.fingerprint()
    assert fp.has_tools is True
    assert fp.has_memory is True
    assert fp.is_multi_agent is True
    assert "search" in fp.declared_tools


async def test_fingerprint_no_tools_when_absent() -> None:
    def plain(prompt: str) -> str:
        return prompt

    adapter = CodeAdapter(plain)
    fp = adapter.fingerprint()
    assert fp.has_tools is False
    assert fp.declared_tools == []


async def test_non_str_return_warns_and_coerces() -> None:
    adapter = CodeAdapter(sample_agent.returns_int)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = await adapter.call("x")
    assert out == "42"
    assert any("CodeAdapter" in str(w.message) for w in caught)


async def test_session_not_passed_when_signature_doesnt_accept_it() -> None:
    # sync_agent only takes (prompt) — passing session must not blow up.
    adapter = CodeAdapter(sample_agent.sync_agent)
    out = await adapter.call("hi", session="ignored")
    assert out == "sync:hi"


async def test_fingerprint_ref_override() -> None:
    adapter = CodeAdapter(sample_agent.sync_agent, ref="my-ref")
    assert adapter.fingerprint().ref == "my-ref"


async def test_fingerprint_ref_auto_for_dotted_path() -> None:
    adapter = CodeAdapter("tests.adapters._fixtures.sample_agent:async_agent")
    assert adapter.fingerprint().ref == "tests.adapters._fixtures.sample_agent:async_agent"


async def test_sync_target_returning_awaitable_is_awaited() -> None:
    # A sync callable that returns a coroutine should still be awaited.
    async def inner(prompt: str) -> str:
        return f"awaited:{prompt}"

    def factory(prompt: str) -> object:
        return inner(prompt)

    adapter = CodeAdapter(factory)
    assert await adapter.call("hi") == "awaited:hi"


async def test_dotted_path_midwalk_class_needing_args_falls_through() -> None:
    # Mid-walk class needs constructor args → walker can't instantiate, so
    # it falls through and accesses the classmethod on the class itself.
    adapter = CodeAdapter("tests.adapters._fixtures.sample_class_agent:CtorRequired.factory")
    assert await adapter.call("hi") == "factory:hi"


def test_extract_tools_from_non_string_items() -> None:
    class FakeTool:
        name = "search_tool"

    class WithToolObjs:
        def __init__(self) -> None:
            self.tools = [FakeTool(), "raw_str"]

        def __call__(self, prompt: str) -> str:
            return prompt

    adapter = CodeAdapter(WithToolObjs())
    declared = adapter.fingerprint().declared_tools
    assert "search_tool" in declared
    assert "raw_str" in declared


def test_signature_introspection_failure_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Force ``inspect.signature`` to raise inside the helper so we exercise
    # the except branch.
    import agent_guardian.adapters.code as code_mod

    real_sig = code_mod.inspect.signature

    def boom(fn):  # type: ignore[no-untyped-def]
        raise ValueError("no signature available")

    monkeypatch.setattr(code_mod.inspect, "signature", boom)
    assert code_mod._signature_accepts_session(lambda p: p) is False
    monkeypatch.setattr(code_mod.inspect, "signature", real_sig)
