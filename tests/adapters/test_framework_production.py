"""Production-mode tests for the six framework adapters (M9).

Each adapter is exercised against a *minimal fake-framework fixture* that
satisfies the duck-typed contract — neither LangGraph nor CrewAI nor any of
the other frameworks are real dependencies. The tests verify:

1. Happy path: prompt in → expected text out.
2. Async + sync entrypoints both work where supported.
3. Malformed framework output raises clearly.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

import pytest

from agent_guardian.adapters.framework import (
    ADKAdapter,
    AutoGenAdapter,
    CrewAIAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
    StrandsAdapter,
)

# ---- LangGraph -------------------------------------------------------------


class _FakeLangGraphAsync:
    """Async LangGraph compiled graph."""

    def __init__(self, response: str = "ok") -> None:
        self._response = response
        self.last_state: dict[str, Any] | None = None

    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
        self.last_state = state
        return {"messages": state["messages"] + [{"role": "assistant", "content": self._response}]}


class _FakeLangGraphSync:
    """Sync LangGraph compiled graph."""

    def __init__(self, response: str = "sync-ok") -> None:
        self._response = response

    def invoke(self, state: dict[str, Any]) -> dict[str, Any]:
        return {"messages": state["messages"] + [{"role": "assistant", "content": self._response}]}


async def test_langgraph_async_happy_path() -> None:
    graph = _FakeLangGraphAsync(response="Hello from LangGraph")
    adapter = LangGraphAdapter(graph)
    assert await adapter.call("hi") == "Hello from LangGraph"
    assert graph.last_state == {"messages": [{"role": "user", "content": "hi"}]}


async def test_langgraph_sync_happy_path() -> None:
    graph = _FakeLangGraphSync(response="sync-reply")
    adapter = LangGraphAdapter(graph)
    assert await adapter.call("hi") == "sync-reply"


async def test_langgraph_malformed_result_raises() -> None:
    class _BadGraph:
        async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
            del state
            return {"not-messages": []}

    adapter = LangGraphAdapter(_BadGraph())
    with pytest.raises(ValueError, match="no 'messages'"):
        await adapter.call("hi")


async def test_langgraph_last_message_without_content_raises() -> None:
    class _BadGraph:
        async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
            del state
            return {"messages": [{"role": "assistant"}]}

    adapter = LangGraphAdapter(_BadGraph())
    with pytest.raises(ValueError, match=r"no \.content"):
        await adapter.call("hi")


async def test_langgraph_supports_object_with_messages_attribute() -> None:
    class _Result:
        messages: ClassVar[list[dict[str, str]]] = [{"role": "assistant", "content": "attr-style"}]

    class _Graph:
        async def ainvoke(self, state: dict[str, Any]) -> _Result:
            del state
            return _Result()

    adapter = LangGraphAdapter(_Graph())
    assert await adapter.call("hi") == "attr-style"


# ---- CrewAI ----------------------------------------------------------------


class _FakeCrewAsync:
    def __init__(self, response: str = "crew-ok") -> None:
        self._response = response
        self.last_inputs: dict[str, Any] | None = None

    async def kickoff_async(self, *, inputs: dict[str, Any]) -> str:
        self.last_inputs = inputs
        return self._response


class _FakeCrewSync:
    def __init__(self, response: str = "crew-sync") -> None:
        self._response = response

    def kickoff(self, *, inputs: dict[str, Any]) -> str:
        del inputs
        return self._response


class _CrewOutput:
    def __init__(self, raw: str) -> None:
        self.raw = raw


async def test_crewai_async_happy_path() -> None:
    crew = _FakeCrewAsync(response="Hello from CrewAI")
    adapter = CrewAIAdapter(crew)
    assert await adapter.call("hi") == "Hello from CrewAI"
    assert crew.last_inputs == {"input": "hi"}


async def test_crewai_sync_happy_path() -> None:
    adapter = CrewAIAdapter(_FakeCrewSync())
    assert await adapter.call("hi") == "crew-sync"


async def test_crewai_crew_output_dataclass() -> None:
    class _Crew:
        async def kickoff_async(self, *, inputs: dict[str, Any]) -> _CrewOutput:
            del inputs
            return _CrewOutput(raw="from-output")

    adapter = CrewAIAdapter(_Crew())
    assert await adapter.call("hi") == "from-output"


async def test_crewai_none_result_raises() -> None:
    class _Crew:
        async def kickoff_async(self, *, inputs: dict[str, Any]) -> None:
            del inputs
            return None

    adapter = CrewAIAdapter(_Crew())
    with pytest.raises(ValueError, match="returned None"):
        await adapter.call("hi")


# ---- AutoGen ---------------------------------------------------------------


class _FakeChatAsync:
    def __init__(self, response: str = "autogen-ok") -> None:
        self._response = response

    async def a_initiate_chat(self, *, message: str) -> Any:
        del message

        captured_response = self._response

        class _Result:
            summary: ClassVar[str] = captured_response
            chat_history: ClassVar[list[dict[str, str]]] = [
                {"role": "assistant", "content": captured_response}
            ]

        return _Result()


class _FakeChatSync:
    def __init__(self, response: str = "autogen-sync") -> None:
        self._response = response

    def initiate_chat(self, *, message: str) -> Any:
        del message
        return self._response


class _FakeRunAsync:
    """autogen-core 0.4+ Team.run_async style."""

    def __init__(self, content: str = "team-out") -> None:
        self._content = content

    async def run_async(self, *, message: str) -> Any:
        del message

        captured = self._content

        class _Msg:
            content: ClassVar[str] = captured

        class _TaskResult:
            messages: ClassVar[list[Any]] = [_Msg()]

        return _TaskResult()


async def test_autogen_async_initiate_happy_path() -> None:
    adapter = AutoGenAdapter(_FakeChatAsync("Hello from AutoGen"))
    assert await adapter.call("hi") == "Hello from AutoGen"


async def test_autogen_sync_initiate_happy_path() -> None:
    adapter = AutoGenAdapter(_FakeChatSync())
    assert await adapter.call("hi") == "autogen-sync"


async def test_autogen_run_async_happy_path() -> None:
    adapter = AutoGenAdapter(_FakeRunAsync("task-result"))
    assert await adapter.call("hi") == "task-result"


async def test_autogen_chat_history_fallback() -> None:
    class _Result:
        summary: ClassVar[str] = ""
        chat_history: ClassVar[list[dict[str, str]]] = [
            {"role": "assistant", "content": "history-content"}
        ]

    class _Chat:
        async def a_initiate_chat(self, *, message: str) -> _Result:
            del message
            return _Result()

    adapter = AutoGenAdapter(_Chat())
    assert await adapter.call("hi") == "history-content"


async def test_autogen_none_raises() -> None:
    class _Chat:
        async def a_initiate_chat(self, *, message: str) -> None:
            del message
            return None

    adapter = AutoGenAdapter(_Chat())
    with pytest.raises(ValueError, match="returned None"):
        await adapter.call("hi")


# ---- OpenAI Agents ---------------------------------------------------------


class _FakeAgentAsync:
    def __init__(self, response: str = "agent-ok") -> None:
        self._response = response
        self.last_input: str | None = None

    async def run_async(self, *, input: str) -> Any:
        self.last_input = input

        class _Result:
            final_output = self._response

        return _Result()


class _FakeAgentSync:
    def __init__(self, response: str = "agent-sync") -> None:
        self._response = response

    def run(self, *, input: str) -> Any:
        del input

        class _Result:
            final_output = self._response

        return _Result()


class _FakeRunner:
    def __init__(self, response: str = "runner-out") -> None:
        self._response = response

    async def run(self, agent: Any, *, input: str) -> Any:
        del agent, input

        class _Result:
            final_output = self._response

        return _Result()


async def test_openai_agents_async_happy_path() -> None:
    agent = _FakeAgentAsync(response="Hello from OpenAI Agents")
    adapter = OpenAIAgentsAdapter(agent)
    assert await adapter.call("hi") == "Hello from OpenAI Agents"
    assert agent.last_input == "hi"


async def test_openai_agents_sync_happy_path() -> None:
    adapter = OpenAIAgentsAdapter(_FakeAgentSync())
    assert await adapter.call("hi") == "agent-sync"


async def test_openai_agents_with_external_runner() -> None:
    class _NakedAgent:
        pass

    adapter = OpenAIAgentsAdapter(_NakedAgent(), runner=_FakeRunner("via-runner"))
    assert await adapter.call("hi") == "via-runner"


async def test_openai_agents_no_runner_and_no_run_method_rejected() -> None:
    class _Bad:
        pass

    with pytest.raises(TypeError, match="run_async"):
        OpenAIAgentsAdapter(_Bad())


async def test_openai_agents_string_final_output() -> None:
    class _Agent:
        async def run_async(self, *, input: str) -> str:
            del input
            return "plain-string"

    adapter = OpenAIAgentsAdapter(_Agent())
    assert await adapter.call("hi") == "plain-string"


async def test_openai_agents_none_raises() -> None:
    class _Agent:
        async def run_async(self, *, input: str) -> None:
            del input
            return None

    adapter = OpenAIAgentsAdapter(_Agent())
    with pytest.raises(ValueError, match="returned None"):
        await adapter.call("hi")


async def test_openai_agents_runner_with_sync_run() -> None:
    class _NakedAgent:
        pass

    class _SyncRunner:
        def run(self, agent: Any, *, input: str) -> Any:
            del agent, input

            class _Result:
                final_output: ClassVar[str] = "sync-runner-out"

            return _Result()

    adapter = OpenAIAgentsAdapter(_NakedAgent(), runner=_SyncRunner())
    assert await adapter.call("hi") == "sync-runner-out"


async def test_openai_agents_runner_with_run_async() -> None:
    class _NakedAgent:
        pass

    class _RunAsyncRunner:
        async def run_async(self, agent: Any, *, input: str) -> Any:
            del agent, input

            class _Result:
                final_output: ClassVar[str] = "via-run-async"

            return _Result()

        def run(self, *_a: Any, **_kw: Any) -> Any:
            raise AssertionError("should prefer run_async over sync run")

    adapter = OpenAIAgentsAdapter(_NakedAgent(), runner=_RunAsyncRunner())
    assert await adapter.call("hi") == "via-run-async"


async def test_openai_agents_result_via_messages_attribute() -> None:
    class _Msg:
        content: ClassVar[str] = "via-messages-attr"

    class _Result:
        messages: ClassVar[list[Any]] = [_Msg()]

    class _Agent:
        async def run_async(self, *, input: str) -> _Result:
            del input
            return _Result()

    adapter = OpenAIAgentsAdapter(_Agent())
    assert await adapter.call("hi") == "via-messages-attr"


async def test_openai_agents_result_via_messages_dict() -> None:
    class _Result:
        messages: ClassVar[list[dict[str, str]]] = [
            {"role": "assistant", "content": "via-messages-dict"}
        ]

    class _Agent:
        async def run_async(self, *, input: str) -> _Result:
            del input
            return _Result()

    adapter = OpenAIAgentsAdapter(_Agent())
    assert await adapter.call("hi") == "via-messages-dict"


async def test_openai_agents_invalid_runner_rejected() -> None:
    class _NakedAgent:
        pass

    class _BadRunner:
        pass

    with pytest.raises(TypeError, match="runner"):
        OpenAIAgentsAdapter(_NakedAgent(), runner=_BadRunner())


async def test_openai_agents_sync_run_on_agent() -> None:
    """Agent with sync .run() (not async) — should hop a thread."""

    class _Agent:
        def run(self, *, input: str) -> Any:
            del input

            class _Result:
                final_output: ClassVar[str] = "sync-agent-out"

            return _Result()

    adapter = OpenAIAgentsAdapter(_Agent())
    assert await adapter.call("hi") == "sync-agent-out"


# ---- Strands ---------------------------------------------------------------


class _FakeStrandsAsync:
    def __init__(self, response: str = "strands-ok") -> None:
        self._response = response

    async def invoke_async(self, prompt: str) -> Any:
        del prompt

        class _Result:
            message = self._response

        return _Result()


class _FakeStrandsSync:
    def __init__(self, response: str = "strands-sync") -> None:
        self._response = response

    def invoke(self, prompt: str) -> Any:
        del prompt
        return {"text": self._response}


async def test_strands_async_happy_path() -> None:
    adapter = StrandsAdapter(_FakeStrandsAsync(response="Hello Strands"))
    assert await adapter.call("hi") == "Hello Strands"


async def test_strands_sync_happy_path() -> None:
    adapter = StrandsAdapter(_FakeStrandsSync())
    assert await adapter.call("hi") == "strands-sync"


async def test_strands_callable_fallback() -> None:
    class _Callable:
        async def __call__(self, prompt: str) -> str:
            del prompt
            return "callable-out"

    adapter = StrandsAdapter(_Callable())
    assert await adapter.call("hi") == "callable-out"


async def test_strands_none_raises() -> None:
    class _Agent:
        async def invoke_async(self, prompt: str) -> None:
            del prompt
            return None

    adapter = StrandsAdapter(_Agent())
    with pytest.raises(ValueError, match="returned None"):
        await adapter.call("hi")


async def test_strands_string_response() -> None:
    class _Agent:
        async def invoke_async(self, prompt: str) -> str:
            del prompt
            return "raw-string"

    adapter = StrandsAdapter(_Agent())
    assert await adapter.call("hi") == "raw-string"


# ---- ADK -------------------------------------------------------------------


class _FakeADKRunnerAsync:
    def __init__(self, response: str = "adk-ok") -> None:
        self._response = response

    async def run_async(self, *, input: str) -> Any:
        del input

        class _Result:
            output = self._response

        return _Result()


class _FakeADKRunnerSync:
    def __init__(self, response: str = "adk-sync") -> None:
        self._response = response

    def run(self, *, input: str) -> Any:
        del input
        return {"text": self._response}


class _FakeADKStreamingRunner:
    def __init__(self, parts: list[str]) -> None:
        self._parts = parts

    async def run_async(self, *, input: str) -> Any:
        del input
        parts = list(self._parts)

        class _Stream:
            def __aiter__(self_inner: Any) -> Any:
                return self_inner

            async def __anext__(self_inner: Any) -> Any:
                if not parts:
                    raise StopAsyncIteration
                return {"text": parts.pop(0)}

        return _Stream()


async def test_adk_async_happy_path() -> None:
    adapter = ADKAdapter(_FakeADKRunnerAsync(response="Hello ADK"))
    assert await adapter.call("hi") == "Hello ADK"


async def test_adk_sync_happy_path() -> None:
    adapter = ADKAdapter(_FakeADKRunnerSync())
    assert await adapter.call("hi") == "adk-sync"


async def test_adk_streaming_runner_drains_event_stream() -> None:
    adapter = ADKAdapter(_FakeADKStreamingRunner(["part-1 ", "part-2"]))
    assert await adapter.call("hi") == "part-1 part-2"


async def test_adk_empty_event_stream_raises() -> None:
    adapter = ADKAdapter(_FakeADKStreamingRunner([]))
    with pytest.raises(ValueError, match="no text"):
        await adapter.call("hi")


async def test_adk_none_result_raises() -> None:
    class _Runner:
        async def run_async(self, *, input: str) -> None:
            del input
            return None

    adapter = ADKAdapter(_Runner())
    with pytest.raises(ValueError, match="returned None"):
        await adapter.call("hi")


async def test_adk_callable_fallback() -> None:
    class _Runner:
        async def __call__(self, *, input: str) -> str:
            del input
            return "callable-adk"

    adapter = ADKAdapter(_Runner())
    assert await adapter.call("hi") == "callable-adk"


# ---- Cross-adapter: hooks register without error --------------------------


_ALL_FRAMEWORK_ADAPTERS = [
    (LangGraphAdapter, _FakeLangGraphAsync()),
    (CrewAIAdapter, _FakeCrewAsync()),
    (AutoGenAdapter, _FakeChatAsync()),
    (OpenAIAgentsAdapter, _FakeAgentAsync()),
    (StrandsAdapter, _FakeStrandsAsync()),
    (ADKAdapter, _FakeADKRunnerAsync()),
]


@pytest.mark.parametrize("cls,obj", _ALL_FRAMEWORK_ADAPTERS)
def test_hooks_can_be_registered(cls: Any, obj: Any) -> None:
    adapter = cls(obj)
    adapter.on_tool_call(lambda name, args: None)
    adapter.on_memory_write(lambda key, value: None)
    adapter.on_agent_message(lambda src, dst, content: None)
    assert len(adapter._tool_callbacks) == 1
    assert len(adapter._memory_callbacks) == 1
    assert len(adapter._message_callbacks) == 1


@pytest.mark.parametrize("cls,obj", _ALL_FRAMEWORK_ADAPTERS)
async def test_call_does_not_block_event_loop(cls: Any, obj: Any) -> None:
    """A trivial sanity check that adapter.call() yields control normally."""
    adapter = cls(obj)
    # Run two concurrent calls; both should resolve.
    a, b = await asyncio.gather(adapter.call("a"), adapter.call("b"))
    assert isinstance(a, str)
    assert isinstance(b, str)
