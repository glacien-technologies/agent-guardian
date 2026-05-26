"""AWS Bedrock Converse API request/response shape."""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.http_shapes.base import HttpShape

__all__ = ["SHAPE", "build_request", "extract_response_text"]


def build_request(
    prompt: str,
    *,
    model: str | None = None,
    session: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "modelId": model or "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "messages": [{"role": "user", "content": [{"text": prompt}]}],
        "inferenceConfig": {"maxTokens": 1024, "temperature": 0.7},
    }
    if session is not None:
        payload["additionalModelRequestFields"] = {"session_id": session}
    if extra:
        payload.update(extra)
    return payload


def extract_response_text(response_json: dict[str, Any]) -> str:
    try:
        message = response_json["output"]["message"]
        blocks = message.get("content") or []
        return "".join(b.get("text", "") for b in blocks if "text" in b)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"bedrock_shape: malformed response: {exc}") from exc


SHAPE = HttpShape(
    name="bedrock",
    build_request=build_request,
    extract_response_text=extract_response_text,
    auth_header_name=None,
    auth_header_format=None,
)
