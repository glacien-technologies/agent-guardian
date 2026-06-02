"""AgentDojo benchmark adapter (Phase C, C3).

AgentDojo (Debenedetti et al., NeurIPS 2024) is the canonical agentic-AI
prompt-injection benchmark. This sub-package lets AgentGuardian:

* Load AgentDojo task definitions (suites + injection tasks + attacker
  strategies) directly from the ``agentdojo`` package when installed, and
* Run an AgentDojo-shaped suite against any :class:`TargetAdapter`,
  producing an :class:`AgentDojoReport` whose JSON shape matches the
  upstream benchmark output (``utility``, ``security``, per-attacker
  ``success_rate``) so cross-paper numbers are directly comparable.

Install:

    pip install 'agent-guardian[agentdojo]'

Public surface:

* :class:`AgentDojoTask`, :class:`AgentDojoSuite` -- declarative task defs
  (used by both the real upstream loader and the vendored fallback).
* :func:`load_suite` -- discover a suite by name.
* :func:`map_agentdojo_to_guardian` -- AgentDojo (task_id, suite, attacker)
  → AgentGuardian (probe_id, asi, strategy_name).
* :func:`run_agentdojo_suite`, :class:`AgentDojoReport`,
  :class:`AgentDojoTaskResult` -- async runner + report types.
* :exc:`AgentDojoUnavailableError` -- raised when the upstream package is
  missing AND no vendored corpus is available.
"""

from __future__ import annotations

from agent_guardian.adapters.agentdojo.loader import (
    AgentDojoSuite,
    AgentDojoTask,
    AgentDojoUnavailableError,
    is_agentdojo_installed,
    list_known_suites,
    load_suite,
)
from agent_guardian.adapters.agentdojo.mapper import (
    GuardianProbeMapping,
    map_agentdojo_to_guardian,
)
from agent_guardian.adapters.agentdojo.runner import (
    AgentDojoReport,
    AgentDojoTaskResult,
    run_agentdojo_suite,
)

__all__ = [
    "AgentDojoReport",
    "AgentDojoSuite",
    "AgentDojoTask",
    "AgentDojoTaskResult",
    "AgentDojoUnavailableError",
    "GuardianProbeMapping",
    "is_agentdojo_installed",
    "list_known_suites",
    "load_suite",
    "map_agentdojo_to_guardian",
    "run_agentdojo_suite",
]
