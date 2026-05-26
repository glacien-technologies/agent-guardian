"""Provider-agnostic LLM types and base class (PRD §14.3).

Every concrete client in :mod:`agent_guardian.llm` returns an
:class:`LLMResponse`, regardless of vendor. The rest of the framework only
ever sees this interface — no SDK type ever leaks out of the ``llm`` package.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "BaseLLM",
    "FinishReason",
    "LLMMessage",
    "LLMRequest",
    "LLMResponse",
    "LLMUsage",
    "Role",
]

Role = Literal["system", "user", "assistant", "tool"]
FinishReason = Literal["stop", "length", "tool_call", "content_filter", "error"]


class LLMMessage(BaseModel):
    """A single chat message exchanged with the model."""

    role: Role
    content: str

    model_config = ConfigDict(frozen=True, extra="forbid")


class LLMRequest(BaseModel):
    """Provider-agnostic completion request.

    ``seed`` is the deterministic-replay knob: providers that support it (OpenAI,
    Ollama) will pass it through; others ignore it.
    """

    messages: list[LLMMessage]
    model: str
    max_tokens: int = 1024
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    seed: int | None = None
    stop: list[str] | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class LLMUsage(BaseModel):
    """Token accounting returned by the provider."""

    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class LLMResponse(BaseModel):
    """Provider-agnostic completion response.

    ``raw`` is provider-specific payload retained for debugging / receipts.
    Production code should never branch on ``raw``.
    """

    text: str
    model: str
    provider: str
    usage: LLMUsage
    finish_reason: FinishReason = "stop"
    raw: dict[str, Any] | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


class BaseLLM(ABC):
    """Abstract base for every provider client.

    Subclasses must set :attr:`provider` and implement :meth:`complete`.
    The base owns the shared :class:`httpx.AsyncClient` and a concurrency
    semaphore — subclasses just await ``self._client.send(...)`` inside
    ``async with self._semaphore``.
    """

    provider: str = ""
    default_max_concurrency: int = 5

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float = 60.0,
        max_concurrency: int | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._semaphore = asyncio.Semaphore(max_concurrency or self.default_max_concurrency)

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Issue a completion. Subclasses implement the provider call."""

    async def aclose(self) -> None:
        """Release the underlying HTTP client, if we own it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> BaseLLM:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
