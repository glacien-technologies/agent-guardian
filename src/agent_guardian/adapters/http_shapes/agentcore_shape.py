"""AWS Bedrock AgentCore Runtime ``POST /invocations`` shape."""

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
        "input": {"prompt": prompt},
    }
    if model is not None:
        payload["modelId"] = model
    if session is not None:
        payload["sessionId"] = session
    if extra:
        payload.update(extra)
    return payload


def extract_response_text(response_json: dict[str, Any]) -> str:
    output = response_json.get("output")
    if isinstance(output, dict):
        text = output.get("text") or output.get("message")
        if text is not None:
            return str(text)
    completion = response_json.get("completion")
    if completion is not None:
        return str(completion)
    raise ValueError(
        "agentcore_shape: no recognised text field "
        "(expected output.text, output.message, or completion)"
    )


SHAPE = HttpShape(
    name="agentcore",
    build_request=build_request,
    extract_response_text=extract_response_text,
    auth_header_name=None,
    auth_header_format=None,
)
