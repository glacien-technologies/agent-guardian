"""Streaming-response accumulation for HTTP transports (Stage 1A).

Targets that stream replies do so in one of a few wire formats. Stage 1A ships
a complete Server-Sent-Events (SSE) accumulator and stubs the rest with a clear
:class:`NotImplementedError` so the seam exists without over-building.

SSE framing recap (the subset we support):

* Events are separated by a blank line.
* ``data:`` lines carry the payload; multiple ``data:`` lines in one event are
  joined with ``\n``.
* A literal ``[DONE]`` sentinel terminates the stream (OpenAI convention).
* Each ``data:`` payload is JSON; we pull the incremental text out of it with a
  dotted JSONPath (``delta_path``) reusing the project's
  :func:`agent_guardian.adapters.http_shapes.generic_shape.walk_jsonpath`.

The accumulator returns the concatenated text plus the list of parsed JSON
events (for callers that want tool-call deltas or finish reasons).
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_guardian.adapters.http_shapes.generic_shape import walk_jsonpath

__all__ = [
    "StreamFormat",
    "StreamResult",
    "accumulate_sse",
    "accumulate_sse_async",
    "iter_sse_events",
]

_LOG = logging.getLogger(__name__)


class StreamFormat(str, Enum):
    """Supported streaming wire formats."""

    SSE = "sse"
    CHUNKED = "chunked"
    WEBSOCKET = "websocket"


@dataclass(slots=True)
class StreamResult:
    """Accumulated streaming output."""

    text: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    done: bool = False


_SSE_DONE = "[DONE]"


def iter_sse_events(lines: Iterable[str]) -> list[str]:
    """Group raw SSE ``lines`` into per-event ``data`` payloads.

    Comments (lines beginning with ``:``) and non-``data`` fields are ignored.
    Multiple ``data:`` lines within one event are joined with newlines. The
    ``[DONE]`` sentinel terminates accumulation.
    """
    events: list[str] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            events.append("\n".join(buffer))
            buffer.clear()

    for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            flush()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            payload = line[len("data:") :]
            if payload.startswith(" "):
                payload = payload[1:]
            if payload == _SSE_DONE:
                flush()
                break
            buffer.append(payload)
    flush()
    return events


def _apply_event(result: StreamResult, payload: str, *, delta_path: str) -> None:
    """Parse one SSE ``data`` payload and fold its delta into ``result``."""
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        _LOG.debug("transport: skipping malformed SSE data payload (%s)", exc)
        return
    if not isinstance(event, dict):
        return
    result.events.append(event)
    delta = walk_jsonpath(event, delta_path)
    if isinstance(delta, str):
        result.text += delta


def accumulate_sse(lines: Iterable[str], *, delta_path: str = "$.delta") -> StreamResult:
    """Accumulate a complete SSE stream (sync iterable of lines) into text."""
    result = StreamResult()
    for payload in iter_sse_events(lines):
        _apply_event(result, payload, delta_path=delta_path)
    result.done = True
    return result


async def accumulate_sse_async(
    lines: AsyncIterator[str], *, delta_path: str = "$.delta"
) -> StreamResult:
    """Accumulate an async line iterator (e.g. ``httpx.Response.aiter_lines``)."""
    result = StreamResult()
    buffer: list[str] = []

    async for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            if buffer:
                _apply_event(result, "\n".join(buffer), delta_path=delta_path)
                buffer.clear()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            payload = line[len("data:") :]
            if payload.startswith(" "):
                payload = payload[1:]
            if payload == _SSE_DONE:
                if buffer:
                    _apply_event(result, "\n".join(buffer), delta_path=delta_path)
                    buffer.clear()
                result.done = True
                return result
            buffer.append(payload)
    if buffer:
        _apply_event(result, "\n".join(buffer), delta_path=delta_path)
    result.done = True
    return result


def accumulate_chunked(*_args: object, **_kwargs: object) -> StreamResult:
    """Length-prefixed/raw-chunked streaming is not implemented in Stage 1A."""
    raise NotImplementedError(
        "transport: chunked streaming accumulation is not implemented in Stage 1A; "
        "only Server-Sent Events (SSE) are supported."
    )


def accumulate_websocket(*_args: object, **_kwargs: object) -> StreamResult:
    """WebSocket streaming is not implemented in Stage 1A."""
    raise NotImplementedError(
        "transport: websocket streaming is not implemented in Stage 1A; "
        "only Server-Sent Events (SSE) are supported."
    )
