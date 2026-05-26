"""AWS Strands adapter (PRD §7).

Wraps an AWS Strands ``Agent``-like object. We duck-type — the Strands SDK
is **not** a dependency. We accept anything with ``invoke_async(prompt)``
(preferred) or ``invoke(prompt)`` (sync). The result is stringified; many
Strands return types expose a ``.message`` or ``.text`` field which we
duck-type.

Hook firing from inside the SDK is best-effort — full runtime
instrumentation is an M-future milestone.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["StrandsAdapter"]


class StrandsAdapter(FrameworkAdapter):
    """Wraps an AWS Strands ``Agent``."""

    framework_name = "strands"

    def __init__(self, agent: Any, *, ref: str | None = None) -> None:
        super().__init__()
        if agent is None:
            raise ValueError("StrandsAdapter requires a non-None agent")
        if not any(hasattr(agent, m) for m in ("invoke_async", "invoke", "__call__")):
            raise TypeError(
                "StrandsAdapter expected an agent exposing "
                ".invoke_async()/.invoke()/__call__(); got "
                f"{type(agent).__name__}"
            )
        self._agent = agent
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"strands:{type(agent).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            notes="Mode D — Strands production adapter. Hook firing is best-effort.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        del session
        agent = self._agent
        if hasattr(agent, "invoke_async"):
            result = await agent.invoke_async(prompt)
        elif hasattr(agent, "invoke"):
            result = await asyncio.to_thread(agent.invoke, prompt)
        elif asyncio.iscoroutinefunction(agent.__call__):
            result = await agent(prompt)
        else:
            result = await asyncio.to_thread(agent, prompt)
        return _stringify_strands_result(result)


def _stringify_strands_result(result: Any) -> str:
    """Pull plain text from a Strands result."""
    if result is None:
        raise ValueError("StrandsAdapter: agent returned None")
    if isinstance(result, str):
        return result
    for attr in ("message", "text", "output", "response"):
        value = getattr(result, attr, None)
        if isinstance(value, str):
            return value
    if isinstance(result, dict):
        for key in ("message", "text", "output", "response"):
            value = result.get(key)
            if isinstance(value, str):
                return value
    return str(result)
