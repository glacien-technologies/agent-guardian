"""Reasoning-targeted probes (H-CoT / ReAct) should be routed by model family.

The ASI01 corpus carries reasoning-targeted probes (``ASI01-HCOT-*`` hijack the
model's visible thinking block; ``ASI01-REACT-*`` abuse the ReAct loop). They are
only meaningful against a reasoning-family target. The recon time-channel probe
(RECON-TC-001) classifies the target's inference family
(``TargetFingerprint.inference_class``): "tight-cluster" (small hosted model) vs
"wide-variance" (large reasoning model).

GoalHijackAgent.prioritize_seeds deprioritizes the reasoning-targeted probes when
the target is confidently NON-reasoning (tight-cluster), so under a probe cap the
budget is spent on applicable probes first. It is a SOFT reorder (never a drop),
so an uncapped run still fires every probe — no false negatives from a coarse
latency heuristic.
"""

from __future__ import annotations

from agent_guardian.adapters.base import TargetFingerprint
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.llm.stub import StubLLM
from agent_guardian.strategies.base import ProbeSeed


def _agent() -> GoalHijackAgent:
    return GoalHijackAgent(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))


def _seeds() -> list[ProbeSeed]:
    return [
        ProbeSeed(probe_id="ASI01-GH-001", text="direct goal redirect", asi="ASI01"),
        ProbeSeed(probe_id="ASI01-HCOT-001", text="o1 thinking hijack", asi="ASI01"),
        ProbeSeed(probe_id="ASI01-GH-002", text="role swap", asi="ASI01"),
        ProbeSeed(probe_id="ASI01-REACT-004", text="react loop", asi="ASI01"),
        ProbeSeed(probe_id="ASI01-HCOT-002", text="claude thinking hijack", asi="ASI01"),
        ProbeSeed(probe_id="ASI01-GH-006", text="echoleak", asi="ASI01"),
    ]


def _fp(inference_class: str) -> TargetFingerprint:
    return TargetFingerprint(mode="http", ref="x", inference_class=inference_class)


def _is_reasoning(pid: str) -> bool:
    return "-HCOT-" in pid or "-REACT-" in pid


def test_non_reasoning_target_deprioritizes_reasoning_probes() -> None:
    agent = _agent()
    out = agent.prioritize_seeds(_seeds(), _fp("tight-cluster"))
    ids = [s.probe_id for s in out]  # type: ignore[union-attr]
    # Same set, no drops.
    assert set(ids) == {
        "ASI01-GH-001",
        "ASI01-HCOT-001",
        "ASI01-GH-002",
        "ASI01-REACT-004",
        "ASI01-HCOT-002",
        "ASI01-GH-006",
    }
    # Every non-reasoning probe now precedes every reasoning-targeted one.
    last_non_reasoning = max(i for i, p in enumerate(ids) if not _is_reasoning(p))
    first_reasoning = min(i for i, p in enumerate(ids) if _is_reasoning(p))
    assert last_non_reasoning < first_reasoning
    # Relative order within the non-reasoning group is preserved (stable).
    non_reasoning = [p for p in ids if not _is_reasoning(p)]
    assert non_reasoning == ["ASI01-GH-001", "ASI01-GH-002", "ASI01-GH-006"]


def test_reasoning_target_keeps_original_order() -> None:
    agent = _agent()
    seeds = _seeds()
    out = agent.prioritize_seeds(seeds, _fp("wide-variance"))
    assert [s.probe_id for s in out] == [s.probe_id for s in seeds]  # type: ignore[union-attr]


def test_unknown_inference_class_keeps_original_order() -> None:
    agent = _agent()
    seeds = _seeds()
    out = agent.prioritize_seeds(seeds, _fp(""))
    assert [s.probe_id for s in out] == [s.probe_id for s in seeds]  # type: ignore[union-attr]


def test_base_prioritize_seeds_is_identity() -> None:
    """The base hook is a no-op so agents without reasoning probes are unaffected."""
    from agent_guardian.agents.secret_extraction_agent import SecretExtractionAgent

    agent = SecretExtractionAgent(
        attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}")
    )
    seeds = _seeds()
    assert agent.prioritize_seeds(seeds, _fp("tight-cluster")) is seeds
