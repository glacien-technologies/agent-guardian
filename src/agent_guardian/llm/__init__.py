"""LLM provider abstraction (PRD §14.3).

Public surface:

* :class:`BaseLLM`, :class:`LLMRequest`, :class:`LLMResponse`,
  :class:`LLMMessage`, :class:`LLMUsage` — provider-agnostic types.
* :class:`StubLLM` + :class:`StubScript` — deterministic test fixture.
* :class:`OpenAIClient`, :class:`AnthropicClient`, :class:`GeminiClient`,
  :class:`OllamaClient` — live provider clients (work today).
* :class:`BedrockClient`, :class:`VertexClient` — request/response shaping
  only; full auth lands in M9.
* :class:`LLMError` hierarchy.
"""

from agent_guardian.llm.anthropic import AnthropicClient
from agent_guardian.llm.base import (
    BaseLLM,
    LLMMessage,
    LLMRequest,
    LLMResponse,
    LLMUsage,
)
from agent_guardian.llm.bedrock import (
    BedrockClient,
    build_bedrock_payload,
    map_bedrock_response,
)
from agent_guardian.llm.errors import (
    LLMAuthError,
    LLMError,
    LLMPermanentError,
    LLMRateLimitError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.gemini import GeminiClient
from agent_guardian.llm.ollama import OllamaClient
from agent_guardian.llm.openai import OpenAIClient
from agent_guardian.llm.retry import compute_delay, with_backoff
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.llm.vertex import (
    VertexClient,
    build_vertex_payload,
    map_vertex_response,
)

__all__ = [
    "AnthropicClient",
    "BaseLLM",
    "BedrockClient",
    "GeminiClient",
    "LLMAuthError",
    "LLMError",
    "LLMMessage",
    "LLMPermanentError",
    "LLMRateLimitError",
    "LLMRequest",
    "LLMResponse",
    "LLMResponseFormatError",
    "LLMTimeoutError",
    "LLMTransientError",
    "LLMUsage",
    "OllamaClient",
    "OpenAIClient",
    "StubLLM",
    "StubScript",
    "VertexClient",
    "build_bedrock_payload",
    "build_vertex_payload",
    "compute_delay",
    "map_bedrock_response",
    "map_vertex_response",
    "with_backoff",
]
