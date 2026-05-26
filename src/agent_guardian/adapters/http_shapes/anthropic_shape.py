"""Anthropic Messages API request/response shape."""

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
        "model": model or "claude-3-5-sonnet-latest",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    if session is not None:
        payload["metadata"] = {"user_id": session}
    if extra:
        payload.update(extra)
    return payload


def extract_response_text(response_json: dict[str, Any]) -> str:
    try:
        blocks = response_json["content"]
        return "".join(
            block.get("text", "")
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        )
    except (KeyError, TypeError) as exc:
        raise ValueError(f"anthropic_shape: malformed response: {exc}") from exc


SHAPE = HttpShape(
    name="anthropic",
    build_request=build_request,
    extract_response_text=extract_response_text,
    auth_header_name="x-api-key",
    auth_header_format="{key}",
)
