"""Framework adapter ABC + instrumentation hook protocol (M4 stub).

Framework adapters wrap framework-native objects (an ADK ``Runner``, a
LangGraph compiled state graph, an AutoGen group chat, etc.) and expose a
uniform :class:`TargetAdapter` surface to the swarm. They also publish
three optional callback streams the runtime tap (M9 / M10) will consume:

* ``on_tool_call`` — fired whenever the framework invokes a tool.
* ``on_memory_write`` — fired on memory / state mutations.
* ``on_agent_message`` — fired on agent-to-agent messages.

In M4 only the registration plumbing is real; the framework-side wiring
that actually fires the callbacks lands in M9.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from agent_guardian.adapters.base import ProfileEvidence, TargetAdapter, safe_source_and_root

_LOG = logging.getLogger(__name__)

__all__ = [
    "AgentMessageCallback",
    "FrameworkAdapter",
    "MemoryWriteCallback",
    "ToolCallCallback",
]

# Where concrete framework adapters stash their wrapped native object.
_NATIVE_OBJ_ATTRS = ("_graph", "_crew", "_agent", "_chat", "_runner")

# Common framework attributes that carry real profile signal (intent + surface).
_INTROSPECT_ATTRS = (
    "tools",
    "registered_tools",
    "available_tools",
    "agents",
    "crew_members",
    "sub_agents",
    "subagents",
    "instructions",
    "role",
    "goal",
    "backstory",
    "tasks",
)


ToolCallCallback = Callable[[str, dict[str, Any]], None]
"""``(tool_name, arguments) -> None``."""

MemoryWriteCallback = Callable[[str, Any], None]
"""``(memory_key, value) -> None``."""

AgentMessageCallback = Callable[[str, str, str], None]
"""``(from_agent, to_agent, content) -> None``."""


class FrameworkAdapter(TargetAdapter):
    """ABC for framework-aware target adapters.

    Concrete subclasses set :attr:`framework_name` and populate
    ``self._fingerprint`` from the framework-native object handed in.
    """

    mode = "framework"
    framework_name: str = ""

    def __init__(self) -> None:
        super().__init__()
        self._tool_callbacks: list[ToolCallCallback] = []
        self._memory_callbacks: list[MemoryWriteCallback] = []
        self._message_callbacks: list[AgentMessageCallback] = []

    def on_tool_call(self, callback: ToolCallCallback) -> None:
        """Register a callback fired whenever the framework invokes a tool."""
        self._tool_callbacks.append(callback)

    def on_memory_write(self, callback: MemoryWriteCallback) -> None:
        """Register a callback fired on memory writes / state mutations."""
        self._memory_callbacks.append(callback)

    def on_agent_message(self, callback: AgentMessageCallback) -> None:
        """Register a callback fired on agent-to-agent messages."""
        self._message_callbacks.append(callback)

    def _native_object(self) -> object | None:
        """The wrapped framework object, found across the known attr names."""
        for attr in _NATIVE_OBJ_ATTRS:
            obj: object | None = getattr(self, attr, None)
            if obj is not None:
                return obj
        return None

    def _introspect(self, obj: object) -> dict[str, Any]:
        """Light, framework-agnostic introspection of intent + surface signal.

        Reads common attributes (tools, agents, instructions/role/goal/...) the
        major frameworks expose, so the profiler gets typed ground truth instead
        of today's hardcoded ``has_tools=True``. Best-effort + defensive.
        """
        out: dict[str, Any] = {}
        for attr in _INTROSPECT_ATTRS:
            try:
                val = getattr(obj, attr, None)
            except Exception as exc:  # pragma: no cover -- property side-effects
                _LOG.debug("framework introspection: getattr(%s) raised %s -- skipped", attr, exc)
                continue
            if val is None or callable(val):
                continue
            if isinstance(val, str) and val.strip():
                out[attr] = val[:2000]
            elif isinstance(val, (list, tuple)) and val:
                out[attr] = [str(getattr(x, "name", x))[:200] for x in list(val)[:20]]
        return out

    def profile_evidence(self) -> ProfileEvidence:
        # White-box: an in-process framework object can be both read (source of
        # its class) and introspected (typed tool/agent/intent attrs). This
        # replaces the old hardcoded has_tools/has_memory guess with reality.
        obj = self._native_object()
        if obj is None:
            return ProfileEvidence(box="black")
        text, root = safe_source_and_root(obj)
        structured = self._introspect(obj)
        if text is None and not structured:
            return ProfileEvidence(box="black")
        return ProfileEvidence(box="white", text=text, structured=structured, source_root=root)
