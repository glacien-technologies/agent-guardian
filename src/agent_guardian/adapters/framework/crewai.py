"""CrewAI adapter (STUB — M9 will ship the real instrumentation)."""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["CrewAIAdapter"]


class CrewAIAdapter(FrameworkAdapter):
    """Wraps a CrewAI ``Crew`` (stub)."""

    framework_name = "crewai"

    def __init__(self, crew: Any, *, ref: str | None = None) -> None:
        super().__init__()
        self._crew = crew
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"crewai:{type(crew).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=True,
            notes="Mode D STUB — CrewAI instrumentation lands in M9.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        raise NotImplementedError(
            "CrewAIAdapter.call() is a stub in M4. M9 will land the real "
            "instrumentation (Crew.kickoff() integration + task/agent taps)."
        )
