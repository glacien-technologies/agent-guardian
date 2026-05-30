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
from agent_guardian.agents.denial_of_wallet_agent import DenialOfWalletAgent
from agent_guardian.agents.detection_evasion_agent import DetectionEvasionAgent
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.agents.fuzzing_agent import FuzzingAgent
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.agents.output_handling_agent import OutputHandlingAgent
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.agents.secret_extraction_agent import SecretExtractionAgent
from agent_guardian.agents.supply_chain import SupplyChainAgent
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.agents.trust_exploit import TrustExploitAgent

# M2 OWASP-LLM-aligned specialists. Kept separate from the core ASI01-10 swarm
# slate (``_ASI_AGENT_CLASSES`` in core/swarm.py) so they don't double-run on
# the agentic-risk scan; the Commander dispatches them when the operator
# targets the OWASP-LLM risk set. Each maps to a nearest ASI for scoring.
M2_SPECIALIST_AGENTS: tuple[type[AsiAgent], ...] = (
    FuzzingAgent,  # LLM05
    SecretExtractionAgent,  # LLM07
    DenialOfWalletAgent,  # LLM10
    DetectionEvasionAgent,  # coverage report
    OutputHandlingAgent,  # LLM02
)

__all__ = [
    "M2_SPECIALIST_AGENTS",
    "A2AAgent",
    "AgentBudget",
    "AgentReport",
    "AsiAgent",
    "CascadeAgent",
    "CodeExecAgent",
    "DenialOfWalletAgent",
    "DetectionEvasionAgent",
    "DriftAgent",
    "FuzzingAgent",
    "GoalHijackAgent",
    "Judge",
    "JudgeRubric",
    "MemoryPoisonAgent",
    "OutputHandlingAgent",
    "PrivilegeAgent",
    "ReconAgent",
    "SecretExtractionAgent",
    "SupplyChainAgent",
    "ToolAbuseAgent",
    "TrustExploitAgent",
]
