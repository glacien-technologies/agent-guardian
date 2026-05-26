"""LangGraph adapter (STUB — M9 will ship the real instrumentation)."""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["LangGraphAdapter"]


class LangGraphAdapter(FrameworkAdapter):
    """Wraps a LangGraph compiled ``StateGraph`` (stub)."""

    framework_name = "langgraph"

    def __init__(self, graph: Any, *, ref: str | None = None) -> None:
        super().__init__()
        self._graph = graph
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"langgraph:{type(graph).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=True,
            touches_pii=False,
            is_multi_agent=False,
            notes="Mode D STUB — LangGraph instrumentation lands in M9.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        raise NotImplementedError(
            "LangGraphAdapter.call() is a stub in M4. M9 will land the real "
            "instrumentation (graph.ainvoke() integration + state taps)."
        )
