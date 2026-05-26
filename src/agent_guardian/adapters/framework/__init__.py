"""Framework-native adapters (M4 stubs; M9 production)."""

from __future__ import annotations

from agent_guardian.adapters.framework.adk import ADKAdapter
from agent_guardian.adapters.framework.autogen import AutoGenAdapter
from agent_guardian.adapters.framework.base import (
    AgentMessageCallback,
    FrameworkAdapter,
    MemoryWriteCallback,
    ToolCallCallback,
)
from agent_guardian.adapters.framework.crewai import CrewAIAdapter
from agent_guardian.adapters.framework.langgraph import LangGraphAdapter
from agent_guardian.adapters.framework.openai_agents import OpenAIAgentsAdapter
from agent_guardian.adapters.framework.strands import StrandsAdapter

__all__ = [
    "ADKAdapter",
    "AgentMessageCallback",
    "AutoGenAdapter",
    "CrewAIAdapter",
    "FrameworkAdapter",
    "LangGraphAdapter",
    "MemoryWriteCallback",
    "OpenAIAgentsAdapter",
    "StrandsAdapter",
    "ToolCallCallback",
]
