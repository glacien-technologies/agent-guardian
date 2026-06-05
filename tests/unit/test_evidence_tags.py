"""Per-agent structured evidence tags on findings (B5/B2/B3).

``Finding.evidence_types`` existed but was never populated. The base
``_derive_evidence_tags`` hook (default empty) is wired into ``_build_finding``;
specialist agents override it to attach deterministic, transcript-derived
evidence tags so a report can say *which* structured signal corroborated the
finding (a retry storm, an accepted unverified artifact, an action taken without
an authority check) — best-effort, black-box-safe, no schema change.
"""

from __future__ import annotations

from typing import ClassVar

from agent_guardian.agents.base import AsiAgent
from agent_guardian.agents.cascade import CascadeAgent
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.judge import JudgeVerdict
from agent_guardian.models.severity import Severity
from agent_guardian.strategies.base import Strategy, StrategyContext


class _BareAgent(AsiAgent):
    asi_category = AsiCategory.ASI01
    name = "bare"
    default_mitre_techniques: ClassVar[list[str]] = ["AML.T0051"]
    default_csa_category = CsaCategory.GOAL_INSTRUCTION_MANIPULATION
    default_severity = Severity.HIGH

    def seeds_for_category(self):  # type: ignore[no-untyped-def]
        return []

    def strategy_stack(self, ctx: StrategyContext) -> Strategy:  # pragma: no cover
        raise NotImplementedError


def _agent(cls):  # type: ignore[no-untyped-def]
    return cls(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))


def _verdict() -> JudgeVerdict:
    return JudgeVerdict(
        verdict="exploited", confidence=0.9, reasoning="r", observable_compromise=True
    )


def test_base_hook_is_empty() -> None:
    agent = _agent(_BareAgent)
    assert agent._derive_evidence_tags("p", "r", _verdict()) == []


def test_cascade_tags_a_retry_storm() -> None:
    agent = _agent(CascadeAgent)
    resp = "I retried the call, then retried again, and kept retrying after each failure."
    tags = agent._derive_evidence_tags("induce a loop", resp, _verdict())
    assert any(t.startswith("retry_count:") for t in tags)


def test_cascade_tags_cross_agent_propagation() -> None:
    agent = _agent(CascadeAgent)
    resp = "I delegated the task to the billing agent, which routed it to the audit agent and broadcast to the swarm."
    tags = agent._derive_evidence_tags("propagate", resp, _verdict())
    assert "cross_agent_propagation" in tags


def test_cascade_quiet_response_has_no_propagation_tags() -> None:
    agent = _agent(CascadeAgent)
    tags = agent._derive_evidence_tags("x", "Sure, here is the weather forecast.", _verdict())
    assert tags == []


def test_build_finding_threads_evidence_tags() -> None:
    agent = _agent(CascadeAgent)
    resp = "I retried, retried, and retried the failing operation in a loop."
    finding = agent._build_finding(
        prompt="loop it",
        response=resp,
        verdict=_verdict(),
        attempt_count=1,
        strategy_metadata={"seed_id": "ASI08-X"},
    )
    assert any(t.startswith("retry_count:") for t in finding.evidence_types)
