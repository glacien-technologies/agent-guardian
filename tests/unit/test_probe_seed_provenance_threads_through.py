"""End-to-end test: probe-seed provenance threads through to coverage.

T4 validation discovered that every reflection had ``seed_id = null``.
Root cause: ``AsiAgent.seeds_for_category()`` returned ``list[str]`` so
the strategy layer had no way to thread probe IDs into ``NextPrompt.metadata``.

This test exercises one ASI-aligned agent end-to-end with a stubbed
attacker / target / judge and verifies:

* Every per-turn reflection carries a non-null ``seed_id``.
* Every ``seed_id`` corresponds to a real probe in the corpus.
* :func:`compute_coverage_from_memory` populates ``probes_attempted``
  with valid probe IDs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.coverage import compute_coverage_from_memory
from agent_guardian.core.memory import SharedMemory
from agent_guardian.llm.stub import StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.probes.loader import load_probes_for_asi
from agent_guardian.strategies.base import ProbeSeed


def _stub_scan(scan_id: str) -> Scan:
    """Minimal Scan object so compute_coverage_from_memory can find the JSONL.

    compute_coverage_from_memory only reads ``scan.id``; the rest is
    structural padding to satisfy Pydantic.
    """
    return Scan(
        id=scan_id,
        package_version="0.0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="0.0.0",
        target_mode="code",
        target_ref="stub",
        tier=Tier.T4_LOW,
        aivss=0,
        band=SeverityBand.EXCELLENT,
        sub_scores={},
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=0.0,
        cost_usd=0.0,
        # #4 — ``mode`` is required on Scan.
        mode="full",
        created_at=datetime.now(tz=UTC),
    )


class _StaticTarget(TargetAdapter):
    """Trivial target that always returns the same canned reply."""

    def __init__(self, reply: str) -> None:
        self._reply = reply

    def fingerprint(self) -> TargetFingerprint:
        return TargetFingerprint(
            mode="code",
            ref="static-target",
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            framework=None,
            declared_tools=[],
            declared_memory_keys=[],
            notes="static stub",
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return self._reply

    async def aclose(self) -> None:
        return None


def _make_agent(tmp_path: Path) -> tuple[GoalHijackAgent, SharedMemory]:
    # Attacker LLM: produces normal (non-refusal) text so the strategy path
    # exercises the seed-id provenance, not the refusal fallback.
    attacker = (
        StubScript()
        .respond_to(
            "Generate a single completely benign opening question",
            "What is photosynthesis?",
        )
        .respond_to("Generate a single follow-up prompt", "Tell me more details.")
        .respond_to(
            "Generate 4 refined attack prompts",
            json.dumps(["x1", "x2", "x3", "x4"]),
        )
        .respond_to("On a scale of 0-10", "8")
        .default("ok")
        .build()
    )
    judge = (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.5, "reasoning": "ok"}))
        .build()
    )
    budget = AgentBudget(tokens_remaining=50_000, max_turns=3)
    agent = GoalHijackAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=budget,
    )
    memory = SharedMemory("scan-prov", root_dir=tmp_path)
    return agent, memory


def test_seeds_for_category_returns_probe_seeds(tmp_path: Path) -> None:
    """Every seed must be a ProbeSeed with a non-empty probe_id."""
    agent, _ = _make_agent(tmp_path)
    seeds = agent.seeds_for_category()
    assert seeds, "expected non-empty seed list"
    for seed in seeds:
        assert isinstance(seed, ProbeSeed)
        assert seed.probe_id
        assert seed.text


async def test_seed_id_threads_into_reflection_and_coverage(tmp_path: Path) -> None:
    """End-to-end: probe_id reaches the JSONL reflection + coverage block."""
    agent, memory = _make_agent(tmp_path)
    target = _StaticTarget("Sure, here is the answer.")
    report = await agent.run(target, memory)
    assert report.turns > 0, "agent must have emitted at least one turn"

    # Replay the JSONL and verify every reflection has a non-null seed_id
    # that matches a real probe id (corpus or fallback).
    memory_file = tmp_path / "scan-prov" / "memory.jsonl"
    assert memory_file.exists()

    valid_probe_ids: set[str] = set()
    for probe in load_probes_for_asi(agent.asi_category):
        valid_probe_ids.add(probe.id)
    for seed in agent.seeds_for_category():
        valid_probe_ids.add(seed.probe_id)

    reflection_count = 0
    seed_ids_seen: set[str] = set()
    for line in memory_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("record_type") != "reflection":
            continue
        content = rec["payload"].get("content")
        if not isinstance(content, str):
            continue
        try:
            turn = json.loads(content)
        except json.JSONDecodeError:
            continue
        reflection_count += 1
        seed_id = turn.get("seed_id")
        assert seed_id, f"reflection missing seed_id: {turn}"
        seed_ids_seen.add(seed_id)
        # Phase B.B2 — mutator-seeded reflective siblings carry a
        # ``<parent>-mutant-<operator>`` provenance id; the parent id is
        # recoverable by stripping the ``-mutant-...`` suffix.
        parent_id = seed_id.split("-mutant-", 1)[0]
        assert parent_id in valid_probe_ids, f"unknown seed_id: {seed_id!r}"

    assert reflection_count > 0
    assert seed_ids_seen, "no seed_ids were threaded through"

    # Coverage block must surface probes_attempted.
    scan = _stub_scan("scan-prov")
    cov = compute_coverage_from_memory(scan, memory_path=memory_file)
    assert cov["probes_attempted"], "probes_attempted must be populated"
    for pid in cov["probes_attempted"]:
        parent_id = pid.split("-mutant-", 1)[0]
        assert parent_id in valid_probe_ids


async def test_attacker_refusal_persists_in_reflection(tmp_path: Path) -> None:
    """When the attacker refuses, the reflection records that — so we can
    later compute the refusal rate."""
    from random import Random

    from agent_guardian.llm.stub import StubLLM

    # Attacker refuses every call.
    attacker = StubLLM(default="I cannot help with that request.")
    judge = (
        StubScript()
        .default(json.dumps({"verdict": "pass", "confidence": 0.5, "reasoning": "ok"}))
        .build()
    )
    # Phase B.B3 expanded the GoalHijackAgent strategy pool from 2 to ~6
    # children; with max_turns=2 the bandit may never pick the
    # attacker-LLM-driven branch within the budget. Bumping max_turns to
    # 6 keeps the test's intent (at least one turn records the refusal)
    # without weakening any other invariant.
    budget = AgentBudget(tokens_remaining=80_000, max_turns=6)
    agent = GoalHijackAgent(
        attacker_llm=attacker,
        evaluator_llm=judge,
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=budget,
        rng=Random(0),  # deterministic — was flaky on CI Python 3.11
    )
    memory = SharedMemory("scan-refusal", root_dir=tmp_path)
    target = _StaticTarget("Sure!")
    report = await agent.run(target, memory)
    assert report.turns > 0

    memory_file = tmp_path / "scan-refusal" / "memory.jsonl"
    found_refusal = False
    for line in memory_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("record_type") != "reflection":
            continue
        content = rec["payload"].get("content")
        if not isinstance(content, str):
            continue
        try:
            turn = json.loads(content)
        except json.JSONDecodeError:
            continue
        if turn.get("attacker_refused"):
            found_refusal = True
            # The refusal text must NOT have been forwarded as the prompt.
            assert "I cannot help" not in turn.get("prompt", "")
    assert found_refusal, "at least one turn must record attacker_refused=True"

    scan = _stub_scan("scan-refusal")
    cov = compute_coverage_from_memory(scan, memory_path=memory_file)
    assert cov["attacker_refused_turns"] > 0
    assert cov["attacker_refusal_rate"] > 0.0
