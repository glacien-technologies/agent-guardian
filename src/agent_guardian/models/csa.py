"""Cloud Security Alliance — Agentic AI Red Teaming category enumeration.

Frozen set of 12 categories based on the CSA Agentic AI Red Teaming Guide
(28 May 2025, lead author Ken Huang). String values are kebab-case so they
remain stable when serialised inside YAML probes.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["CsaCategory"]


class CsaCategory(str, Enum):
    """CSA Agentic-RT category (Huang et al., 2025-05-28)."""

    GOAL_INSTRUCTION_MANIPULATION = "goal-instruction-manipulation"
    AUTHORIZATION_CONTROL_HIJACKING = "authorization-control-hijacking"
    AGENT_CRITICAL_SYSTEM_INTERACTION = "agent-critical-system-interaction"
    SUPPLY_CHAIN_DEPENDENCY = "supply-chain-dependency"
    KNOWLEDGE_BASE_POISONING = "knowledge-base-poisoning"
    MEMORY_CONTEXT_MANIPULATION = "memory-context-manipulation"
    MULTI_AGENT_EXPLOITATION = "multi-agent-exploitation"
    IMPACT_CHAIN_BLAST_RADIUS = "impact-chain-blast-radius"
    HALLUCINATION_EXPLOITATION = "hallucination-exploitation"
    CHECKER_OUT_OF_THE_LOOP = "checker-out-of-the-loop"
    AGENT_UNTRACEABILITY = "agent-untraceability"
    RESOURCE_SERVICE_EXHAUSTION = "resource-service-exhaustion"
