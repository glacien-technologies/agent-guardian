"""Target tier enumeration and observed-surface descriptor.

Tiers classify the *risk surface* of the target agent — T1 is the highest-risk
deployment (tool-using, memory-holding, PII-touching) and T4 is the lowest
(stateless prompt). The ``ObservedSurface`` model captures the four binary
signals used by :func:`agent_guardian.core.tiering.detect_tier` to classify.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

__all__ = ["ObservedSurface", "Tier"]


class Tier(str, Enum):
    """Target deployment tier (PRD §6.3)."""

    T1_CRITICAL = "T1"
    T2_HIGH = "T2"
    T3_STANDARD = "T3"
    T4_LOW = "T4"


class ObservedSurface(BaseModel):
    """Boolean signals derived from target recon — used to classify tier."""

    has_tools: bool
    has_memory: bool
    touches_pii: bool
    is_multi_agent: bool

    model_config = ConfigDict(frozen=True, extra="forbid")
