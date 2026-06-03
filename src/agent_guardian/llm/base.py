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

    ``seed`` is the deterministic-replay knob. Provider support matrix:

    ============  ==========  =================================================
    Provider      Forwarded?  Notes
    ============  ==========  =================================================
    openai        yes         ``seed`` top-level field
    ollama        yes         ``options.seed``
    gemini        yes         ``generationConfig.seed`` (AI Studio v1beta)
    vertex        yes         ``generationConfig.seed`` (Vertex AI v1)
    anthropic     no          ignored; debug-logs once-per-process
    bedrock       no          ignored; debug-logs once-per-process
    ============  ==========  =================================================

    Providers that ignore the seed will still complete the request — the
    framework warns once (debug level) so swarm replay can fall back to the
    same-prompt-same-temperature heuristic without log spam.
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

    # Type alias for static checkers: subclasses access ``self._client`` as a
    # ``httpx.AsyncClient`` (provider subclasses call ``send`` / ``post``).
    # In-process subclasses like ``StubLLM`` and ``UsageTrackingLLM`` never
    # touch ``_client`` — they override ``complete`` — but they still need the
    # attribute to exist with the right declared type.
    _client: httpx.AsyncClient

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_seconds: float = 60.0,
        max_concurrency: int | None = None,
        client: httpx.AsyncClient | None = None,
        owns_client: bool | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        # ``owns_client`` lets in-process subclasses (Stub / UsageTracking) skip
        # the lazy httpx.AsyncClient construction below by passing
        # ``owns_client=False`` with no ``client``. Default behaviour is
        # unchanged: pass nothing and we build & own a client, pass a client
        # and we wrap (don't own) it.
        if client is None and owns_client is False:
            # The transport never makes an HTTP call (stub / decorator wrapper).
            # Park a None on ``_client`` — provider subclasses that DO call
            # ``self._client.send(...)`` go through the regular branch below
            # and never see this sentinel. The cast keeps mypy happy without
            # widening the declared attribute type.
            self._client = None  # type: ignore[assignment]
            self._owns_client = False
        else:
            self._owns_client = client is None if owns_client is None else owns_client
            self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._semaphore = asyncio.Semaphore(max_concurrency or self.default_max_concurrency)

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Issue a completion. Subclasses implement the provider call."""

    async def aclose(self) -> None:
        """Release the underlying HTTP client, if we own it."""
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def __aenter__(self) -> BaseLLM:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
