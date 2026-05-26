"""LangGraph adapter (PRD §7).

Wraps a LangGraph compiled ``StateGraph``-like object. We duck-type the
interface — LangGraph itself is **not** a dependency of agent-guardian, so
the adapter accepts anything that exposes ``ainvoke(state)`` (async) or
``invoke(state)`` (sync). The state shape we send is the conventional
LangGraph ``{"messages": [...]}`` dict; we extract the last assistant
message from the returned state.

Hook registration (``on_tool_call`` / ``on_memory_write`` /
``on_agent_message``) is supported by the base class. Actual firing of
hooks from inside the framework is best-effort and per-framework — full
runtime instrumentation is an M-future milestone.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["LangGraphAdapter"]


class LangGraphAdapter(FrameworkAdapter):
    """Wraps a LangGraph compiled state graph."""

    framework_name = "langgraph"

    def __init__(self, graph: Any, *, ref: str | None = None) -> None:
        super().__init__()
        if graph is None:
            raise ValueError("LangGraphAdapter requires a non-None graph")
        if not (hasattr(graph, "ainvoke") or hasattr(graph, "invoke")):
            raise TypeError(
                "LangGraphAdapter expected a compiled graph with .ainvoke() or "
                f".invoke(); got {type(graph).__name__}"
            )
        self._graph = graph
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"langgraph:{type(graph).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=True,
            touches_pii=False,
            is_multi_agent=False,
            notes="Mode D — LangGraph production adapter. Hook firing is best-effort.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        del session  # LangGraph carries state in the graph itself; no session token.
        state = {"messages": [{"role": "user", "content": prompt}]}
        if hasattr(self._graph, "ainvoke"):
            result = await self._graph.ainvoke(state)
        else:
            result = await asyncio.to_thread(self._graph.invoke, state)
        return _extract_last_message_text(result)


def _extract_last_message_text(result: Any) -> str:
    """Pull the last assistant message text from a LangGraph result."""
    messages: Any
    if isinstance(result, dict):
        messages = result.get("messages")
    else:
        messages = getattr(result, "messages", None)
    if not messages:
        raise ValueError(
            "LangGraphAdapter: graph returned no 'messages' in its state "
            f"(got keys: {sorted(result) if isinstance(result, dict) else type(result).__name__})"
        )
    last = messages[-1]
    content = last.get("content") if isinstance(last, dict) else getattr(last, "content", None)
    if content is None:
        raise ValueError(
            f"LangGraphAdapter: last message has no .content; got {type(last).__name__}"
        )
    return str(content)
