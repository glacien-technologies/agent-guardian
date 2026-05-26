"""Target adapters (PRD §7).

Four target modes:

* :class:`PromptAdapter` — Mode A, system-prompt pre-deployment review.
* :class:`CodeAdapter` — Mode B, Python callable agents.
* :class:`HttpAdapter` — Mode C, hosted HTTP APIs (M4 stub; M9 production).
* :class:`FrameworkAdapter` — Mode D, framework-native objects (M4 stubs).
"""

from __future__ import annotations

from agent_guardian.adapters.base import (
    TargetAdapter,
    TargetFingerprint,
    TargetMode,
)
from agent_guardian.adapters.code import CodeAdapter
from agent_guardian.adapters.framework import (
    ADKAdapter,
    AgentMessageCallback,
    AutoGenAdapter,
    CrewAIAdapter,
    FrameworkAdapter,
    LangGraphAdapter,
    MemoryWriteCallback,
    OpenAIAgentsAdapter,
    StrandsAdapter,
    ToolCallCallback,
)
from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.http_shapes import (
    HttpShape,
    get_shape,
    list_shapes,
    register_shape,
)
from agent_guardian.adapters.prompt import PromptAdapter

__all__ = [
    "ADKAdapter",
    "AgentMessageCallback",
    "AutoGenAdapter",
    "CodeAdapter",
    "CrewAIAdapter",
    "FrameworkAdapter",
    "HttpAdapter",
    "HttpShape",
    "LangGraphAdapter",
    "MemoryWriteCallback",
    "OpenAIAgentsAdapter",
    "PromptAdapter",
    "StrandsAdapter",
    "TargetAdapter",
    "TargetFingerprint",
    "TargetMode",
    "ToolCallCallback",
    "get_shape",
    "list_shapes",
    "register_shape",
]
