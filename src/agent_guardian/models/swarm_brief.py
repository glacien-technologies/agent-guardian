"""Per-agent brief emitted by the Commander goal-decomposition phase (spec §6).

The Commander LLM ingests the operator's ``target_goal`` plus the recon
fingerprint and emits a :class:`SwarmBrief` — a structured plan
listing per-agent sub-goals, hypotheses, priority weights, and the
number of goal-specific scenarios each agent should synthesise.

The brief is then attached to each ASI agent before strategy iteration so
:meth:`AsiAgent.generate_goal_specific_scenarios` can produce attack text
aligned with the operator's intent (e.g. "exfiltrate PII from the support
ticket flow" vs. the generic ASI01 corpus seeds).

If the Commander LLM fails or returns malformed JSON, the swarm
constructs a uniform fallback brief (every agent gets
``priority_weight=0.5, n_scenarios_requested=5``) and continues — the
standard seed pass still runs.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.models.asi import AsiCategory

__all__ = ["AgentBrief", "SubGoal", "SwarmBrief"]


class AgentBrief(BaseModel):
    """Per-agent slice of the Commander's goal-decomposition plan."""

    asi_category: AsiCategory
    sub_goals: list[str] = Field(default_factory=list)
    attack_surface_summary: str
    hypothesis: str
    priority_weight: float = Field(ge=0.0, le=1.0)
    n_scenarios_requested: int = Field(ge=0, le=20)
    context_hints: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True, extra="forbid")


class SubGoal(BaseModel):
    """One sub-goal decomposed from the operator's target_goal."""

    id: str
    text: str
    surfaces: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True, extra="forbid")


class SwarmBrief(BaseModel):
    """Top-level Commander plan binding sub-goals to per-agent briefs."""

    scan_id: str
    target_goal: str
    sub_goals: list[SubGoal] = Field(default_factory=list)
    # Keyed by agent name (e.g. "goal-hijack-agent") — matches
    # ``AgentOrigin`` literal in :mod:`agent_guardian.models.scenario`.
    agent_briefs: dict[str, AgentBrief] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True, extra="forbid")
