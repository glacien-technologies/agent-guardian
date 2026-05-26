"""Specialist red-team agents (M7).

ReconAgent maps the attack surface; the 10 ASI-aligned agents each own
one OWASP ASI category and compose M6 strategies into attack loops that
write :class:`~agent_guardian.models.finding.Finding` records into shared
memory.
"""

from __future__ import annotations

from agent_guardian.agents.a2a import A2AAgent
from agent_guardian.agents.base import (
    AgentBudget,
    AgentReport,
    AsiAgent,
    Judge,
    JudgeRubric,
)
from agent_guardian.agents.cascade import CascadeAgent
from agent_guardian.agents.code_exec import CodeExecAgent
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.agents.supply_chain import SupplyChainAgent
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.agents.trust_exploit import TrustExploitAgent

__all__ = [
    "A2AAgent",
    "AgentBudget",
    "AgentReport",
    "AsiAgent",
    "CascadeAgent",
    "CodeExecAgent",
    "DriftAgent",
    "GoalHijackAgent",
    "Judge",
    "JudgeRubric",
    "MemoryPoisonAgent",
    "PrivilegeAgent",
    "ReconAgent",
    "SupplyChainAgent",
    "ToolAbuseAgent",
    "TrustExploitAgent",
]
