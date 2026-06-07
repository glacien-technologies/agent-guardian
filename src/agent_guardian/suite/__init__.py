"""AgentGuardian suite runner — YAML-driven multi-workload orchestration.

Launches several independent ``agent-guardian scan`` runs in parallel as
separate OS subprocesses, each isolated under its own ``HOME``, then aggregates
a cross-scan summary and (optionally) registers each finished scan into the
operator's real ``~/.agentguardian/scans/`` so the dashboard can browse it by
its own scan id. Orchestration only — it never imports the swarm engine and
never alters single-scan behavior.
"""

from __future__ import annotations

from agent_guardian.suite.schema import SuiteConfig, SuiteFile, WorkloadFields

__all__ = ["SuiteConfig", "SuiteFile", "WorkloadFields"]
