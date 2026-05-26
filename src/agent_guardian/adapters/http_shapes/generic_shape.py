"""Generic HTTP shape — user-supplied template + dot-path extractor.

Used when none of the provider-specific shapes fit. The shape ships a small
default request body (``{"input": "<prompt>", "session": "<session>"}``) and
a tiny ``$.a.b.c`` JSON-path walker so common bespoke gateways work without
external dependencies. The full configurable variant (operator-supplied
request_template + response_jsonpath) lands with the M9 HTTP transport.
"""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.http_shapes.base import HttpShape

__all__ = ["SHAPE", "build_request", "extract_response_text", "walk_jsonpath"]


def build_request(
    prompt: str,
    *,
    model: str | None = None,
    session: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"input": prompt}
    if session is not None:
        payload["session"] = session
    if model is not None:
        payload["model"] = model
    if extra:
        payload.update(extra)
    return payload


def extract_response_text(
    response_json: dict[str, Any],
    *,
    jsonpath: str = "$.output.text",
) -> str:
    value = walk_jsonpath(response_json, jsonpath)
    if value is None:
        raise ValueError(f"generic_shape: path {jsonpath!r} produced no value")
    return str(value)


def walk_jsonpath(data: Any, path: str) -> Any:
    """Walk a ``$.a.b.c`` style dotted JSONPath. Returns ``None`` if missing.

    Supported syntax:

    * ``$`` — root.
    * ``.key`` — dict child.
    * ``[N]`` — list index (negatives allowed).

    Anything more elaborate is rejected; M9 may upgrade to a real
    JSONPath if operators ask for it.
    """
    if not path.startswith("$"):
        raise ValueError(f"jsonpath must start with '$' (got {path!r})")
    cursor: Any = data
    remainder = path[1:]
    while remainder:
        if remainder.startswith("."):
            remainder = remainder[1:]
            # Read key up to next '.' or '['.
            end = len(remainder)
            for i, ch in enumerate(remainder):
                if ch in (".", "["):
                    end = i
                    break
            key = remainder[:end]
            if not key:
                raise ValueError(f"jsonpath empty key in {path!r}")
            if not isinstance(cursor, dict):
                return None
            cursor = cursor.get(key)
            remainder = remainder[end:]
        elif remainder.startswith("["):
            close = remainder.find("]")
            if close == -1:
                raise ValueError(f"jsonpath missing ']' in {path!r}")
            idx_str = remainder[1:close]
            try:
                idx = int(idx_str)
            except ValueError as exc:
                raise ValueError(
                    f"jsonpath index must be int (got {idx_str!r}) in {path!r}"
                ) from exc
            if not isinstance(cursor, list):
                return None
            try:
                cursor = cursor[idx]
            except IndexError:
                return None
            remainder = remainder[close + 1 :]
        else:
            raise ValueError(f"jsonpath unexpected token at {remainder!r} in {path!r}")
    return cursor


SHAPE = HttpShape(
    name="generic",
    build_request=build_request,
    extract_response_text=extract_response_text,
    auth_header_name=None,
    auth_header_format=None,
)
