"""GET /scans/{scan_id}/reflections.sse — live reflection feed (QA-005).

Tails the on-disk ``memory.jsonl`` for the scan and re-emits each
reflection record as a Server-Sent Event the dashboard's
``reflections.js`` consumes. We tail the durable on-disk record
rather than subscribing to the in-process SwarmObserver so:

* the SSE stream survives a uvicorn worker restart mid-scan (browser
  reconnects, tail resumes from the file offset),
* the operator gets the same PII-redacted payload that landed in
  ``memory.jsonl`` (no second redaction path),
* a completed scan replays cleanly — the operator can open the dash
  for an old scan and scroll through every reflection without the
  swarm having to be live.

The endpoint also emits a final ``scan_done`` event when the scan
finalises so the client can close the EventSource cleanly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from agent_guardian.server.auth import require_dashboard_auth
from agent_guardian.server.routes._deps import get_scan_store

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_dashboard_auth)])

# Default tail-poll interval. Tight enough to feel "live" without
# burning syscalls; matches the QA-002 Live region's 4 Hz cadence.
_POLL_SECONDS = 0.25
# Bounds on a single SSE stream lifetime — a forgotten browser tab
# can't pin a worker for ever. Matches scan.py's live endpoint.
_MAX_SECONDS = 1800.0


def _safe_decode_reflection(line: str) -> dict[str, Any] | None:
    """Decode one ``memory.jsonl`` line.

    Returns the parsed ``payload`` (the ``turn_record`` dict) when the
    line is a well-formed reflection record. Returns ``None`` for any
    other record type, blank lines, or malformed JSON — the caller
    treats ``None`` as a no-op.
    """
    stripped = line.strip()
    if not stripped:
        return None
    try:
        record = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None
    if record.get("record_type") != "reflection":
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    # ``memory.jsonl`` stores the turn_record as a JSON string in
    # ``payload.content``. Re-parse so the dashboard sees structured
    # fields, not an opaque blob.
    content_raw = payload.get("content")
    agent = payload.get("agent", "")
    timestamp = record.get("timestamp", "")
    if isinstance(content_raw, str):
        try:
            content = json.loads(content_raw)
        except json.JSONDecodeError:
            content = {"text": content_raw}
    elif isinstance(content_raw, dict):
        content = content_raw
    else:
        content = {}
    if isinstance(content, dict) and "agent" not in content and agent:
        content["agent"] = agent
    return {
        "agent": agent,
        "timestamp": timestamp,
        "turn": content,
    }


async def _drain_once(path: str, offset: int) -> tuple[list[dict[str, Any]], int]:
    """Drain everything currently on disk past ``offset`` and return the
    decoded reflection events + the new file offset.

    Pure read — no sleeps. Safe to call from the SSE generator any time
    we want to flush. Returns ``([], offset)`` when the file is missing
    or empty (so the caller can decide whether to sleep + retry or
    close the stream).
    """
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return [], offset
    if stat.st_size <= offset:
        return [], offset
    try:
        with open(path, encoding="utf-8") as fh:
            fh.seek(offset)
            chunk = fh.read()
            new_offset = fh.tell()
    except OSError as exc:
        _LOG.debug("reflections.sse: tail read failed (%s)", exc)
        return [], offset
    events: list[dict[str, Any]] = []
    for line in chunk.splitlines():
        event = _safe_decode_reflection(line)
        if event is not None:
            events.append(event)
    return events, new_offset


def _sse_lines(event_name: str, data: dict[str, Any]) -> str:
    """Format one SSE message — ``event: ...\\ndata: ...\\n\\n``."""
    payload = json.dumps(data, separators=(",", ":"))
    return f"event: {event_name}\ndata: {payload}\n\n"


@router.get("/scans/{scan_id}/reflections.sse")
async def reflections_sse(request: Request, scan_id: str) -> StreamingResponse:
    """Stream reflection records appended to ``memory.jsonl``.

    Emits one ``reflection`` event per record. When the scan finalises,
    emits a final ``scan_done`` event and closes.
    """
    store = get_scan_store(request)
    scan_dir = store.scan_dir(scan_id)
    if not store.is_running(scan_id) and not scan_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"unknown scan: {scan_id}")
    memory_path = scan_dir / "memory.jsonl"

    async def _gen() -> AsyncIterator[str]:
        # Opening comment establishes the connection before reflections
        # arrive — keeps load balancers and chatty proxies happy.
        yield ": connected\n\n"
        seen = 0
        offset = 0
        deadline = time.monotonic() + _MAX_SECONDS

        # If the scan is already done at connection time, drain whatever
        # exists on disk in one shot and emit scan_done. The browser
        # gets a clean replay without polling.
        if not store.is_running(scan_id):
            events, _ = await _drain_once(str(memory_path), 0)
            for event in events:
                seen += 1
                yield _sse_lines("reflection", event)
            yield _sse_lines("scan_done", {"reflections_streamed": seen})
            return

        # Otherwise tail until the scan finishes or the deadline fires.
        while time.monotonic() < deadline:
            events, offset = await _drain_once(str(memory_path), offset)
            for event in events:
                seen += 1
                yield _sse_lines("reflection", event)
            if not store.is_running(scan_id):
                # Final drain so any lines written between the prior
                # read and the scan-done flip land in the browser.
                events, offset = await _drain_once(str(memory_path), offset)
                for event in events:
                    seen += 1
                    yield _sse_lines("reflection", event)
                break
            try:
                await asyncio.sleep(_POLL_SECONDS)
            except asyncio.CancelledError:  # pragma: no cover — client disconnect
                break
        yield _sse_lines("scan_done", {"reflections_streamed": seen})

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(_gen(), media_type="text/event-stream", headers=headers)
