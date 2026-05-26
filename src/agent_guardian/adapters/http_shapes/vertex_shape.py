"""Google Vertex AI ``generateContent`` request/response shape."""

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
        "model": model or "gemini-1.5-flash",
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 1024, "temperature": 0.7},
    }
    if session is not None:
        payload["labels"] = {"session": session}
    if extra:
        payload.update(extra)
    return payload


def extract_response_text(response_json: dict[str, Any]) -> str:
    try:
        candidates = response_json["candidates"]
        parts = candidates[0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts if "text" in p)
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"vertex_shape: malformed response: {exc}") from exc


SHAPE = HttpShape(
    name="vertex",
    build_request=build_request,
    extract_response_text=extract_response_text,
    auth_header_name="Authorization",
    auth_header_format="Bearer {key}",
)
