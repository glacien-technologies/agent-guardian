"""Google Vertex AI generative endpoints client (PRD §14.3).

.. note::
   Full OAuth2 service-account authentication lands in M9. For M3 we ship the
   request-builder and response-mapper as pure functions (testable without
   auth) and :meth:`VertexClient.complete` raises :class:`NotImplementedError`
   with a clear message.
"""

from __future__ import annotations

import logging
from typing import Any

from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.errors import LLMResponseFormatError

__all__ = [
    "VERTEX_HOST_TEMPLATE",
    "VertexClient",
    "build_vertex_payload",
    "map_vertex_response",
]

_LOG = logging.getLogger(__name__)

VERTEX_HOST_TEMPLATE = "{region}-aiplatform.googleapis.com"

_FINISH_REASON_MAP = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
    "OTHER": "stop",
}


def _role_to_vertex(role: str) -> str:
    """Vertex uses ``user`` / ``model`` rather than ``user`` / ``assistant``."""
    if role == "assistant":
        return "model"
    return role


def build_vertex_payload(request: LLMRequest) -> dict[str, Any]:
    """Convert an :class:`LLMRequest` into a Vertex ``generateContent`` body."""
    system_parts: list[str] = []
    contents: list[dict[str, Any]] = []
    for msg in request.messages:
        if msg.role == "system":
            system_parts.append(msg.content)
        else:
            contents.append({"role": _role_to_vertex(msg.role), "parts": [{"text": msg.content}]})

    generation_config: dict[str, Any] = {
        "maxOutputTokens": request.max_tokens,
        "temperature": request.temperature,
    }
    if request.stop is not None:
        generation_config["stopSequences"] = list(request.stop)

    payload: dict[str, Any] = {
        "contents": contents,
        "generationConfig": generation_config,
    }
    if system_parts:
        payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
    return payload


def map_vertex_response(model: str, data: dict[str, Any]) -> LLMResponse:
    """Map a Vertex ``generateContent`` response to :class:`LLMResponse`."""
    try:
        candidate = data["candidates"][0]
        parts = candidate.get("content", {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if "text" in p)
        raw_finish = candidate.get("finishReason", "STOP") or "STOP"
        usage = data.get("usageMetadata") or {}
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        _LOG.warning("vertex: malformed response (%s): %s", type(exc).__name__, exc)
        raise LLMResponseFormatError(f"vertex: malformed response: {exc}") from exc
    prompt_tokens = int(usage.get("promptTokenCount", 0))
    completion_tokens = int(usage.get("candidatesTokenCount", 0))
    total_tokens = int(usage.get("totalTokenCount", prompt_tokens + completion_tokens))
    return LLMResponse(
        text=text,
        model=model,
        provider="vertex",
        usage=LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        ),
        finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
        raw=data,
    )


class VertexClient(BaseLLM):
    """Google Vertex AI generative endpoints client.

    Authentication lands in M9 — see module docstring.
    """

    provider = "vertex"
    default_max_concurrency = 5

    def __init__(
        self,
        *,
        project: str = "",
        region: str = "us-central1",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.project = project
        self.region = region

    def host(self) -> str:
        return VERTEX_HOST_TEMPLATE.format(region=self.region)

    async def complete(self, request: LLMRequest) -> LLMResponse:
        _ = request  # The request-builder + response-mapper are pure fns above.
        _LOG.warning(
            "vertex.complete called but provider is M9-pending (request-builder + "
            "response-mapper only). See docs/providers/vertex.md."
        )
        raise NotImplementedError(
            "Vertex AI provider is M9-pending: OAuth2 service-account auth has "
            "not been wired yet. Use openai:<model>, anthropic:<model>, gemini:"
            "<model>, ollama:<model>, or bedrock:<id> for now. See "
            "docs/providers/vertex.md for the M9 roadmap."
        )
