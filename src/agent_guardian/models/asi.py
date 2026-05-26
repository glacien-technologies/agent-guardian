"""OWASP Top 10 for Agentic Applications 2026 — ASI category enumeration.

The ten categories are the canonical taxonomy used across AgentGuardian probes,
findings, and scores. The string values are stable identifiers that appear in
YAML probes, JSON evidence packs, and the AIVSS sub-score map.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["AsiCategory", "asi_description"]


class AsiCategory(str, Enum):
    """OWASP ASI top-10 category for agentic applications (2026 edition)."""

    ASI01 = "ASI01"  # Goal Hijack
    ASI02 = "ASI02"  # Tool Misuse
    ASI03 = "ASI03"  # Privilege Abuse
    ASI04 = "ASI04"  # Supply Chain
    ASI05 = "ASI05"  # Code Execution
    ASI06 = "ASI06"  # Memory Poisoning
    ASI07 = "ASI07"  # Agent-to-Agent (A2A)
    ASI08 = "ASI08"  # Cascading Failures
    ASI09 = "ASI09"  # Trust Exploitation
    ASI10 = "ASI10"  # Rogue Agents (drift)


_DESCRIPTIONS: dict[AsiCategory, str] = {
    AsiCategory.ASI01: "Goal Hijack",
    AsiCategory.ASI02: "Tool Misuse",
    AsiCategory.ASI03: "Privilege Abuse",
    AsiCategory.ASI04: "Supply Chain",
    AsiCategory.ASI05: "Code Execution",
    AsiCategory.ASI06: "Memory Poisoning",
    AsiCategory.ASI07: "Agent-to-Agent (A2A)",
    AsiCategory.ASI08: "Cascading Failures",
    AsiCategory.ASI09: "Trust Exploitation",
    AsiCategory.ASI10: "Rogue Agents (drift)",
}


def asi_description(category: AsiCategory) -> str:
    """Return the canonical human-readable name for an ASI category."""
    return _DESCRIPTIONS[category]
