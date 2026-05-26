"""Target adapters (PRD §7) — base interface plus production Modes A & B."""

from __future__ import annotations

from agent_guardian.adapters.base import (
    TargetAdapter,
    TargetFingerprint,
    TargetMode,
)
from agent_guardian.adapters.code import CodeAdapter
from agent_guardian.adapters.prompt import PromptAdapter

__all__ = [
    "CodeAdapter",
    "PromptAdapter",
    "TargetAdapter",
    "TargetFingerprint",
    "TargetMode",
]
