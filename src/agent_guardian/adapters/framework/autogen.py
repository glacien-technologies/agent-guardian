"""Microsoft AutoGen adapter (STUB — M9 will ship the real instrumentation)."""

from __future__ import annotations

from typing import Any

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter

__all__ = ["AutoGenAdapter"]


class AutoGenAdapter(FrameworkAdapter):
    """Wraps an AutoGen ``GroupChat`` / agent (stub)."""

    framework_name = "autogen"

    def __init__(self, group_chat: Any, *, ref: str | None = None) -> None:
        super().__init__()
        self._group_chat = group_chat
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=ref or f"autogen:{type(group_chat).__name__}",
            framework=self.framework_name,
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=True,
            notes="Mode D STUB — AutoGen instrumentation lands in M9.",
        )

    async def call(self, _prompt: str, *, session: str | None = None) -> str:
        raise NotImplementedError(
            "AutoGenAdapter.call() is a stub in M4. M9 will land the real "
            "instrumentation (GroupChatManager integration + message taps)."
        )
