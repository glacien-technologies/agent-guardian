"""Streaming-response accumulation for HTTP transports (Stage 1A / Stage 2).

Targets that stream replies do so in one of a few wire formats. We ship a
complete Server-Sent-Events (SSE) accumulator and a chunked-transfer accumulator
(newline-delimited JSON / raw text concatenation). WebSocket remains a clear
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
    "accumulate_chunked",
    "accumulate_chunked_async",
    "accumulate_sse",
    "accumulate_sse_async",
    "accumulate_websocket",
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


def _apply_chunk(result: StreamResult, chunk: str, *, delta_path: str | None) -> None:
    """Fold one chunked-transfer payload into ``result``.

    When ``delta_path`` is set each non-empty chunk is parsed as a standalone
    JSON document (newline-delimited JSON / JSON-lines) and its delta appended;
    malformed lines are skipped. When ``delta_path`` is ``None`` the chunk is a
    raw text fragment and is concatenated verbatim.
    """
    if delta_path is None:
        result.text += chunk
        return
    stripped = chunk.strip()
    if not stripped:
        return
    try:
        event = json.loads(stripped)
    except json.JSONDecodeError as exc:
        _LOG.debug("transport: skipping malformed chunked JSON payload (%s)", exc)
        return
    if not isinstance(event, dict):
        return
    result.events.append(event)
    delta = walk_jsonpath(event, delta_path)
    if isinstance(delta, str):
        result.text += delta


def accumulate_chunked(
    chunks: Iterable[str], *, delta_path: str | None = "$.delta"
) -> StreamResult:
    """Accumulate a chunked-transfer stream into text.

    Two modes, selected by ``delta_path``:

    * ``delta_path`` set (default) — each chunk/line is newline-delimited JSON
      (JSON-lines); the dotted-path delta of each object is concatenated.
    * ``delta_path=None`` — chunks are raw text fragments concatenated verbatim.

    ``chunks`` is any sync iterable of strings (e.g. lines from
    ``httpx.Response.iter_lines`` or text fragments from ``iter_text``).
    """
    result = StreamResult()
    for chunk in chunks:
        _apply_chunk(result, chunk, delta_path=delta_path)
    result.done = True
    return result


async def accumulate_chunked_async(
    chunks: AsyncIterator[str], *, delta_path: str | None = "$.delta"
) -> StreamResult:
    """Async counterpart of :func:`accumulate_chunked` for ``aiter_lines`` etc."""
    result = StreamResult()
    async for chunk in chunks:
        _apply_chunk(result, chunk, delta_path=delta_path)
    result.done = True
    return result


def accumulate_websocket(*_args: object, **_kwargs: object) -> StreamResult:
    """WebSocket streaming is not implemented in Stage 1A."""
    raise NotImplementedError(
        "transport: websocket streaming is not implemented in Stage 1A; "
        "only Server-Sent Events (SSE) and chunked transfer are supported."
    )
