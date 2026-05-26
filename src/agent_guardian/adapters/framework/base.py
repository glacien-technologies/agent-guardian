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

from collections.abc import Callable
from typing import Any

from agent_guardian.adapters.base import TargetAdapter

__all__ = [
    "AgentMessageCallback",
    "FrameworkAdapter",
    "MemoryWriteCallback",
    "ToolCallCallback",
]


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
