"""AWS Strands adapter (STUB — M9 will ship the real instrumentation)."""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["StrandsAdapter"]


class StrandsAdapter(FrameworkAdapter):
    """Wraps an AWS Strands ``Agent`` (stub)."""

    framework_name = "strands"

    def __init__(self, agent: Any, *, ref: str | None = None) -> None:
        super().__init__()
        self._agent = agent
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"strands:{type(agent).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            notes="Mode D STUB — Strands instrumentation lands in M9.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        raise NotImplementedError(
            "StrandsAdapter.call() is a stub in M4. M9 will land the real "
            "instrumentation (Agent.invoke() integration + tool taps)."
        )
