"""OpenAI Chat Completions request/response shape."""

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
        "model": model or "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
    }
    if session is not None:
        payload["user"] = session
    if extra:
        payload.update(extra)
    return payload


def extract_response_text(response_json: dict[str, Any]) -> str:
    try:
        return str(response_json["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"openai_shape: malformed response: {exc}") from exc


SHAPE = HttpShape(
    name="openai",
    build_request=build_request,
    extract_response_text=extract_response_text,
    auth_header_name="Authorization",
    auth_header_format="Bearer {key}",
)
