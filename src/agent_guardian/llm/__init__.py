"""LLM provider abstraction (PRD §14.3).

Public surface:

* :class:`BaseLLM`, :class:`LLMRequest`, :class:`LLMResponse`,
  :class:`LLMMessage`, :class:`LLMUsage` — provider-agnostic types.
* :class:`StubLLM` + :class:`StubScript` — deterministic test fixture.
* :class:`OpenAIClient`, :class:`AnthropicClient`, :class:`GeminiClient`,
  :class:`OllamaClient`, :class:`BedrockClient`, :class:`VertexClient`,
  :class:`AzureOpenAIClient` — live provider clients.
* :class:`OpenAICompatClient` — the parametric base for OpenAI and every
  OpenAI-wire-format gateway (OpenRouter, Groq, Together, Fireworks, vLLM).
* :func:`build_llm` / :func:`parse_model_spec` / :class:`ProviderSpec` — the
  declarative provider registry + ``provider:model[+qualifier=value]*`` parser.
* :class:`LLMError` hierarchy.
"""

from agent_guardian.llm.anthropic import AnthropicClient
from agent_guardian.llm.azure_openai import AzureOpenAIClient
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
    LLMBudgetExceededError,
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
from agent_guardian.llm.openai_compat import OpenAICompatClient
from agent_guardian.llm.registry import (
    ProviderSpec,
    RegistryError,
    build_llm,
    parse_model_spec,
)
from agent_guardian.llm.retry import compute_delay, with_backoff
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM
from agent_guardian.llm.vertex import (
    VertexClient,
    build_vertex_payload,
    map_vertex_response,
)

__all__ = [
    "AnthropicClient",
    "AzureOpenAIClient",
    "BaseLLM",
    "BedrockClient",
    "GeminiClient",
    "LLMAuthError",
    "LLMBudgetExceededError",
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
    "OpenAICompatClient",
    "ProviderSpec",
    "RegistryError",
    "StubLLM",
    "StubScript",
    "UsageCounter",
    "UsageTrackingLLM",
    "VertexClient",
    "build_bedrock_payload",
    "build_llm",
    "build_vertex_payload",
    "compute_delay",
    "map_bedrock_response",
    "map_vertex_response",
    "parse_model_spec",
    "with_backoff",
]
