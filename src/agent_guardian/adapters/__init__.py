"""Target adapters (PRD §7) — base interface, Modes A & B, plus HTTP shapes."""

from __future__ import annotations

from agent_guardian.adapters.base import (
    TargetAdapter,
    TargetFingerprint,
    TargetMode,
)
from agent_guardian.adapters.code import CodeAdapter
from agent_guardian.adapters.http_shapes import (
    HttpShape,
    get_shape,
    list_shapes,
    register_shape,
)
from agent_guardian.adapters.prompt import PromptAdapter

__all__ = [
    "CodeAdapter",
    "HttpShape",
    "PromptAdapter",
    "TargetAdapter",
    "TargetFingerprint",
    "TargetMode",
    "get_shape",
    "list_shapes",
    "register_shape",
]
