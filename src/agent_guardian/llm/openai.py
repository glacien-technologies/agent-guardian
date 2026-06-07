"""OpenAI Chat Completions client (PRD §14.3).

Implements the bare-minimum surface AgentGuardian needs: synchronous chat
completion mapped to :class:`LLMResponse`. Streaming, tools, vision, etc. are
out of scope for the OSS edition.

The actual wire logic lives in :class:`OpenAICompatClient` — every
OpenAI-compatible gateway shares it. ``OpenAIClient`` is a thin subclass that
pins the canonical OpenAI ``base_url`` (``https://api.openai.com/v1``) and the
``openai`` provider label. The ``/v1`` is part of the base URL, NOT appended by
the client (so a custom ``base_url`` must already carry its own path prefix —
reviewer correction #1).
"""

from __future__ import annotations

from typing import Any

from agent_guardian.llm.openai_compat import OpenAICompatClient

__all__ = ["OpenAIClient"]

_DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAIClient(OpenAICompatClient):
    """OpenAI Chat Completions provider client."""

    provider = "openai"
    default_max_concurrency = 10

    def __init__(self, *, base_url: str | None = None, **kwargs: Any) -> None:
        super().__init__(
            provider="openai",
            base_url=base_url or _DEFAULT_BASE_URL,
            **kwargs,
        )
