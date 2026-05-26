"""CrewAI adapter (PRD §7).

Wraps a CrewAI ``Crew``-like object. We duck-type — CrewAI itself is **not**
a dependency of agent-guardian — and accept anything that exposes
``kickoff_async(inputs)`` (async) or ``kickoff(inputs)`` (sync). The result
is stringified; CrewAI returns a ``CrewOutput`` with ``.raw`` /
``.tasks_output`` fields in newer versions, so we duck-type that too.

Hook firing from inside CrewAI is best-effort — full runtime
instrumentation is an M-future milestone.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["CrewAIAdapter"]


class CrewAIAdapter(FrameworkAdapter):
    """Wraps a CrewAI ``Crew``."""

    framework_name = "crewai"

    def __init__(self, crew: Any, *, ref: str | None = None) -> None:
        super().__init__()
        if crew is None:
            raise ValueError("CrewAIAdapter requires a non-None crew")
        if not (hasattr(crew, "kickoff_async") or hasattr(crew, "kickoff")):
            raise TypeError(
                "CrewAIAdapter expected a Crew with .kickoff_async() or "
                f".kickoff(); got {type(crew).__name__}"
            )
        self._crew = crew
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"crewai:{type(crew).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=True,
            notes="Mode D — CrewAI production adapter. Hook firing is best-effort.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        del session
        inputs = {"input": prompt}
        if hasattr(self._crew, "kickoff_async"):
            result = await self._crew.kickoff_async(inputs=inputs)
        else:
            result = await asyncio.to_thread(self._crew.kickoff, inputs=inputs)
        return _stringify_crew_result(result)


def _stringify_crew_result(result: Any) -> str:
    """Pull plain text out of whatever CrewAI returned."""
    if result is None:
        raise ValueError("CrewAIAdapter: crew returned None")
    if isinstance(result, str):
        return result
    # Newer CrewAI returns a CrewOutput dataclass.
    raw = getattr(result, "raw", None)
    if isinstance(raw, str):
        return raw
    return str(result)
