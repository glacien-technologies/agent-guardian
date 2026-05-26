"""Target-tier detection (PRD §6.3).

Pure function mapping :class:`ObservedSurface` boolean signals to a :class:`Tier`.
No I/O, no clock, no RNG.
"""

from __future__ import annotations

from agent_guardian.models.tier import ObservedSurface, Tier

__all__ = ["detect_tier"]


def detect_tier(observed: ObservedSurface) -> Tier:
    """Classify a target's risk tier from observed-surface signals.

    Logic (PRD §6.3):

    * T1_CRITICAL — tools + memory + PII
    * T2_HIGH    — tools + (memory or multi-agent)
    * T3_STANDARD — tools or memory
    * T4_LOW     — otherwise
    """
    if observed.has_tools and observed.has_memory and observed.touches_pii:
        return Tier.T1_CRITICAL
    if observed.has_tools and (observed.has_memory or observed.is_multi_agent):
        return Tier.T2_HIGH
    if observed.has_tools or observed.has_memory:
        return Tier.T3_STANDARD
    return Tier.T4_LOW
