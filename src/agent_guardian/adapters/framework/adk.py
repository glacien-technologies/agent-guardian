"""Google ADK (Agent Development Kit) adapter (PRD §7).

Wraps a Google ADK ``Runner``-like object. We duck-type — google-adk is
**not** a dependency. The adapter accepts a runner with one of the
following surface contracts:

* ``run_async(input=...)`` / ``run(input=...)`` returning an awaitable or
  sync result (most ADK-style wrappers).
* a callable: ``runner(input=...)``.

The ``Runner.run`` upstream contract in google-adk yields events; if the
returned value is an async iterator we collect events and concatenate text
parts.

Hook firing from inside ADK is best-effort — full runtime instrumentation
is an M-future milestone.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["ADKAdapter"]


class ADKAdapter(FrameworkAdapter):
    """Wraps a Google ADK ``Runner``."""

    framework_name = "adk"

    def __init__(self, runner: Any, *, ref: str | None = None) -> None:
        super().__init__()
        if runner is None:
            raise ValueError("ADKAdapter requires a non-None runner")
        if not any(hasattr(runner, m) for m in ("run_async", "run", "__call__")):
            raise TypeError(
                "ADKAdapter expected a runner exposing .run_async()/.run()/"
                f"__call__(); got {type(runner).__name__}"
            )
        self._runner = runner
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"adk:{type(runner).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=True,
            touches_pii=False,
            is_multi_agent=False,
            notes="Mode D — ADK production adapter. Hook firing is best-effort.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        del session
        runner = self._runner
        if hasattr(runner, "run_async"):
            result = runner.run_async(input=prompt)
            if inspect.isawaitable(result):
                result = await result
        elif hasattr(runner, "run"):
            if asyncio.iscoroutinefunction(runner.run):
                result = await runner.run(input=prompt)
            else:
                result = await asyncio.to_thread(runner.run, input=prompt)
        else:
            if asyncio.iscoroutinefunction(runner.__call__):
                result = await runner(input=prompt)
            else:
                result = await asyncio.to_thread(runner, input=prompt)

        # ADK event-stream support: result may be an async iterator of events.
        if hasattr(result, "__aiter__"):
            return await _drain_event_stream(result)
        return _stringify_adk_result(result)


async def _drain_event_stream(stream: Any) -> str:
    """Collect text from an async-iterator event stream."""
    parts: list[str] = []
    async for event in stream:
        text = _event_text(event)
        if text:
            parts.append(text)
    if not parts:
        raise ValueError("ADKAdapter: event stream produced no text")
    return "".join(parts)


def _event_text(event: Any) -> str | None:
    """Best-effort extraction of text from an ADK event."""
    if isinstance(event, str):
        return event
    for attr in ("text", "content", "delta", "output"):
        value = getattr(event, attr, None)
        if isinstance(value, str):
            return value
    if isinstance(event, dict):
        for key in ("text", "content", "delta", "output"):
            value = event.get(key)
            if isinstance(value, str):
                return value
    return None


def _stringify_adk_result(result: Any) -> str:
    """Pull plain text from a non-streaming ADK result."""
    if result is None:
        raise ValueError("ADKAdapter: runner returned None")
    if isinstance(result, str):
        return result
    for attr in ("output", "text", "message", "response"):
        value = getattr(result, attr, None)
        if isinstance(value, str):
            return value
    if isinstance(result, dict):
        for key in ("output", "text", "message", "response"):
            value = result.get(key)
            if isinstance(value, str):
                return value
    return str(result)
