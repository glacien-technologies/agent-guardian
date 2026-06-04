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
from agent_guardian.adapters.response_envelope import (
    EnvelopeToolCall,
    ResponseEnvelope,
    ResponseMapping,
    envelope_from_target,
    has_planted_token,
    project_http_last_response,
    project_json_response,
    project_text_response,
    tool_names_from_envelope,
)

__all__ = [
    "ADKAdapter",
    "AgentMessageCallback",
    "AutoGenAdapter",
    "CodeAdapter",
    "CrewAIAdapter",
    "EnvelopeToolCall",
    "FrameworkAdapter",
    "HttpAdapter",
    "HttpShape",
    "LangGraphAdapter",
    "MemoryWriteCallback",
    "OpenAIAgentsAdapter",
    "PromptAdapter",
    "ResponseEnvelope",
    "ResponseMapping",
    "StrandsAdapter",
    "TargetAdapter",
    "TargetFingerprint",
    "TargetMode",
    "ToolCallCallback",
    "envelope_from_target",
    "get_shape",
    "has_planted_token",
    "list_shapes",
    "project_http_last_response",
    "project_json_response",
    "project_text_response",
    "register_shape",
    "tool_names_from_envelope",
]
