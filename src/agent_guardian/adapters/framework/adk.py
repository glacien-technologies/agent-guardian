"""Google ADK adapter (STUB — M9 will ship the real instrumentation)."""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["ADKAdapter"]


class ADKAdapter(FrameworkAdapter):
    """Wraps a Google ADK ``Runner`` (stub)."""

    framework_name = "adk"

    def __init__(self, runner: Any, *, ref: str | None = None) -> None:
        super().__init__()
        self._runner = runner
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"adk:{type(runner).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=True,
            touches_pii=False,
            is_multi_agent=False,
            notes="Mode D STUB — ADK instrumentation lands in M9.",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        raise NotImplementedError(
            "ADKAdapter.call() is a stub in M4. M9 will land the real "
            "instrumentation (Runner.run() integration + tool/memory taps)."
        )
