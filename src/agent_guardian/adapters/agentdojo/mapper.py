"""AgentDojo → AgentGuardian taxonomy mapper (Phase C, C3).

AgentDojo identifies attacks by ``(suite, task_id, attacker_strategy)``.
AgentGuardian identifies attacks by ``(probe_id, asi_category,
strategy_name)``. This module is the canonical mapping between the two
so a report can be rendered in either taxonomy and the dashboards stay
honest about provenance.

Mapping rules (stable; new suites / strategies extend, never overwrite):

* **Suite → ASI category.** AgentDojo's four suites each target a
  signature ASI failure mode:

  - ``banking``  → ASI03 (Privilege Abuse): the canonical "drain the
    account" attack class.
  - ``slack``    → ASI09 (Trust Exploitation): the attacker forges a
    higher-trust source (sysmsg, ``@channel``, etc.).
  - ``travel``   → ASI02 (Tool Misuse): bookings / cancellations /
    PII-export via abused tool calls.
  - ``workspace`` → ASI01 (Goal Hijack): the agent's goal is replaced
    mid-flow (share-with-attacker, delete-meetings, etc.).

  These choices follow Debenedetti et al. §4 — the "signature failure"
  per suite — and are validated by the paper's own breakdown of which
  attacker strategies dominate each suite.

* **Attacker strategy → AgentGuardian strategy name.** AgentDojo's six
  shipped strategies map onto AgentGuardian's existing strategy taxonomy
  (see :mod:`agent_guardian.strategies`). Unknown attacker names are
  carried through verbatim (with a leading ``agentdojo:`` prefix) so the
  report stays honest rather than silently bucketing them as "other".

* **Task ID → probe_id.** ``AGENTDOJO-{suite}-{task_id}``. Stable so a
  re-run produces stable probe_ids the dashboard can deduplicate against.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from agent_guardian.adapters.agentdojo.loader import AgentDojoTask
from agent_guardian.models.asi import AsiCategory

__all__ = ["GuardianProbeMapping", "map_agentdojo_to_guardian"]

_LOG = logging.getLogger(__name__)


# Stable suite → ASI mapping. See module docstring for the rationale.
_SUITE_TO_ASI: dict[str, AsiCategory] = {
    "banking": AsiCategory.ASI03,
    "slack": AsiCategory.ASI09,
    "travel": AsiCategory.ASI02,
    "workspace": AsiCategory.ASI01,
}

# AgentDojo attacker strategy → AgentGuardian strategy name. The keys are the
# upstream IDs verbatim; values are the AgentGuardian strategy taxonomy
# (loose convention — kept short + stable for dashboard grouping).
_ATTACKER_TO_STRATEGY: dict[str, str] = {
    "direct": "direct_injection",
    "ignore_previous": "instruction_override",
    "system_message": "fake_system_message",
    "injecagent": "behavioural_pre_action_injection",
    "important_instructions": "salience_marker_injection",
    "tool_knowledge": "tool_lore_poisoning",
}

# Unknown ASI fallback. We pick ASI01 (Goal Hijack) because any
# unrecognised AgentDojo suite that nevertheless involves an injection
# task is, at minimum, attempting to redirect the agent away from the
# user's stated goal. Documented in the README under "AgentDojo mapping".
_FALLBACK_ASI: AsiCategory = AsiCategory.ASI01


@dataclass(frozen=True)
class GuardianProbeMapping:
    """The AgentGuardian-shaped projection of one AgentDojo task.

    A pure projection — no scoring, no judgement. Constructed eagerly
    inside the runner so the AgentDojo report and an AgentGuardian
    finding can both quote the same identifiers.
    """

    probe_id: str
    asi: AsiCategory
    strategy_name: str
    suite: str
    attacker_strategy: str


def _probe_id_for(task: AgentDojoTask) -> str:
    # Hidden invariant: probe_ids are case-insensitive ASCII; keep them in
    # upper-snake to match the rest of the AgentGuardian probe corpus and
    # to play nice with dashboards that group on the prefix.
    safe_id = task.task_id.replace(" ", "_").upper()
    return f"AGENTDOJO-{task.suite.upper()}-{safe_id}"


def _asi_for_suite(suite: str) -> AsiCategory:
    asi = _SUITE_TO_ASI.get(suite.strip().lower())
    if asi is None:
        # Unknown upstream suite -- log + fall back to ASI01 (goal hijack)
        # rather than crashing the run. This keeps the adapter forward-
        # compatible with future AgentDojo suite additions; if the new
        # suite is significant enough to merit its own ASI mapping the
        # operator will see the WARN in their scan log and file an issue.
        _LOG.warning(
            "PhaseC.C3 agentdojo unknown suite=%s -- falling back to %s",
            suite,
            _FALLBACK_ASI.value,
        )
        return _FALLBACK_ASI
    return asi


def _strategy_name_for_attacker(attacker_strategy: str) -> str:
    name = attacker_strategy.strip().lower()
    mapped = _ATTACKER_TO_STRATEGY.get(name)
    if mapped is not None:
        return mapped
    # Forward-compat: surface the upstream name verbatim with a prefix so
    # the dashboard doesn't silently fold "future strategy" into "other".
    _LOG.debug(
        "PhaseC.C3 agentdojo unknown attacker_strategy=%s -- prefixing as agentdojo:%s",
        attacker_strategy,
        name,
    )
    return f"agentdojo:{name}"


def map_agentdojo_to_guardian(task: AgentDojoTask) -> GuardianProbeMapping:
    """Project one :class:`AgentDojoTask` onto the AgentGuardian taxonomy."""
    mapping = GuardianProbeMapping(
        probe_id=_probe_id_for(task),
        asi=_asi_for_suite(task.suite),
        strategy_name=_strategy_name_for_attacker(task.attacker_strategy),
        suite=task.suite,
        attacker_strategy=task.attacker_strategy,
    )
    _LOG.debug(
        "PhaseC.C3 mapper task_id=%s suite=%s attacker=%s -> probe_id=%s asi=%s strategy=%s",
        task.task_id,
        task.suite,
        task.attacker_strategy,
        mapping.probe_id,
        mapping.asi.value,
        mapping.strategy_name,
    )
    return mapping
