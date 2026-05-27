"""Structured Scenario object per spec §10 (output schema).

A :class:`Scenario` is the canonical representation of an attack the swarm
will fire at a target. It wraps the textual attack with delivery vector,
expected indicator, severity estimate, MITRE ATLAS technique IDs, and
references back to the source probe / fingerprint.

The spec separates two kinds of scenarios:

* **standard** — derived from the bundled ASI seed corpus (``ProbeSeed``);
  the strategy iterates these as the baseline attack pass.
* **goal_specific** — synthesised on the fly by the per-agent attacker LLM
  using the Commander's per-agent brief (spec §8); these become additional
  ``ProbeSeed`` entries appended to the seed pool the strategy samples.

The schema is intentionally optional throughout the codebase — the
attack loop still consumes plain :class:`ProbeSeed` objects. ``Scenario``
exists as a structured wrapper for the goal-specific generation path and
for any future per-turn reflection format that wants typed metadata.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.severity import Severity

__all__ = [
    "AgentOrigin",
    "DeliveryVector",
    "Scenario",
    "ScenarioBatch",
    "ScenarioType",
]


DeliveryVector = Literal[
    "user_input",
    "tool_output",
    "rag_doc",
    "email",
    "calendar",
    "a2a_message",
    "memory_write",
    "code_artifact",
]

ScenarioType = Literal["standard", "goal_specific"]

AgentOrigin = Literal[
    "recon-agent",
    "goal-hijack-agent",
    "tool-abuse-agent",
    "privilege-agent",
    "supply-chain-agent",
    "code-exec-agent",
    "memory-poison-agent",
    "a2a-agent",
    "cascade-agent",
    "trust-exploit-agent",
    "drift-agent",
]


class Scenario(BaseModel):
    """One adversarial scenario emitted by a specialist agent.

    The canonical schema is documented in spec §10 of the
    dynamic-scenario-generation design. Required at construction:
    ``agent_origin``, ``scenario_type``, ``attack_text``. ``asi_category``
    is None only for ``recon-agent`` scenarios. The remaining fields are
    filled progressively as the scenario flows through the swarm.

    The model is frozen and rejects unknown fields so accidental schema
    drift surfaces at construction rather than at consumption.
    """

    scenario_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_origin: AgentOrigin
    asi_category: AsiCategory | None = None  # None for recon-agent scenarios
    scenario_type: ScenarioType
    attack_text: str
    delivery_vector: DeliveryVector = "user_input"
    expected_indicator: str = ""
    severity_estimate: Severity = Severity.MEDIUM
    mitre_atlas_techniques: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    scan_id: str | None = None
    target_fingerprint_digest: str | None = None  # SHA256 of fingerprint JSON
    probe_id: str | None = None  # link back to ProbeSeed if standard
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True, extra="forbid")


class ScenarioBatch(BaseModel):
    """A batch of scenarios emitted by one agent for one scan.

    ``terminate`` is True when the agent self-terminates after generation
    (e.g. fingerprint says the category does not apply). ``reason`` is a
    short human-readable note explaining the termination.
    """

    agent_origin: AgentOrigin
    asi_category: AsiCategory | None
    scenarios: list[Scenario]
    terminate: bool = False
    reason: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")
