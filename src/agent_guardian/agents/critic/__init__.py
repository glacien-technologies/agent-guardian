"""Ensemble critic (M2 Pattern 6).

A separate adversarial reviewer that must accept a finding before it is
reported. Two layers, mirroring Buttercup's QEAgent (program-level validator) +
ReflectionAgent (LLM critic):

* Layer 1 — re-run the PoV in a fresh sandbox; assert reliability clears the gate.
* Layer 2 — an LLM judge scores a structured rubric (evidence, specificity,
  novelty, false-positive risk).

No finding bypasses the critic.
"""

from agent_guardian.agents.critic.critic_agent import CriticAgent, CriticVerdict

__all__ = ["CriticAgent", "CriticVerdict"]
