"""AWS Bedrock Converse API client (PRD §14.3).

.. note::
   Full SigV4 signing lands in M9. For M3 we ship the request-builder and
   response-mapper as pure functions (testable without auth) and
   :meth:`BedrockClient.complete` raises :class:`NotImplementedError` with a
   clear message pointing operators at the upcoming M9 work.

This split lets every downstream consumer code against :class:`BedrockClient`
from day one, while the auth layer matures.
"""

from __future__ import annotations

from typing import Any

from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.errors import LLMResponseFormatError

__all__ = [
    "BEDROCK_HOST_TEMPLATE",
    "BedrockClient",
    "build_bedrock_payload",
    "map_bedrock_response",
]

BEDROCK_HOST_TEMPLATE = "bedrock-runtime.{region}.amazonaws.com"

_FINISH_REASON_MAP = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "tool_use": "tool_call",
    "guardrail_intervened": "content_filter",
}


def build_bedrock_payload(request: LLMRequest) -> dict[str, Any]:
    """Convert an :class:`LLMRequest` into a Bedrock Converse request body.

    Pure function — no AWS auth, no I/O. Exposed for direct unit-testing
    until SigV4 lands in M9.
    """
    system_parts: list[dict[str, Any]] = []
    messages: list[dict[str, Any]] = []
    for msg in request.messages:
        if msg.role == "system":
            system_parts.append({"text": msg.content})
        else:
            messages.append({"role": msg.role, "content": [{"text": msg.content}]})

    payload: dict[str, Any] = {
        "messages": messages,
        "inferenceConfig": {
            "maxTokens": request.max_tokens,
            "temperature": request.temperature,
        },
    }
    if system_parts:
        payload["system"] = system_parts
    if request.stop is not None:
        payload["inferenceConfig"]["stopSequences"] = list(request.stop)
    return payload


def map_bedrock_response(model: str, data: dict[str, Any]) -> LLMResponse:
    """Map a Bedrock Converse response payload to :class:`LLMResponse`.

    Pure function — exposed for direct unit-testing until SigV4 lands in M9.
    """
    try:
        message = data["output"]["message"]
        blocks = message.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if "text" in b)
        usage = data.get("usage") or {}
        raw_finish = data.get("stopReason") or "end_turn"
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise LLMResponseFormatError(f"bedrock: malformed response: {exc}") from exc
    prompt_tokens = int(usage.get("inputTokens", 0))
    completion_tokens = int(usage.get("outputTokens", 0))
    total_tokens = int(usage.get("totalTokens", prompt_tokens + completion_tokens))
    return LLMResponse(
        text=text,
        model=model,
        provider="bedrock",
        usage=LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        ),
        finish_reason=_FINISH_REASON_MAP.get(raw_finish, "stop"),  # type: ignore[arg-type]
        raw=data,
    )


class BedrockClient(BaseLLM):
    """AWS Bedrock Converse provider client.

    Authentication lands in M9 — see module docstring.
    """

    provider = "bedrock"
    default_max_concurrency = 5

    def __init__(self, *, region: str = "us-east-1", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.region = region

    def host(self) -> str:
        return BEDROCK_HOST_TEMPLATE.format(region=self.region)

    async def complete(self, request: LLMRequest) -> LLMResponse:
        raise NotImplementedError(
            "Bedrock SigV4 authentication lands in M9. Use StubLLM in tests, "
            "OpenAIClient / AnthropicClient / OllamaClient in development."
        )
