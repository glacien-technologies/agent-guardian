"""Provenance pin: Finding.mitre_atlas + Finding.csa_category must come from
the source probe YAML, not the agent class-default.

A previous design used the agent's ``default_mitre_techniques`` /
``default_csa_category`` even when the seed was a real corpus probe with
divergent authored framework mappings — the probe's authored intent never
reached the SARIF / dashboard / coverage. This test pins:

* ASI10-DR-006 (self-replicate-via-api) carries a 2-element MITRE list
  (``AI Agent Context Poisoning`` + ``Modify AI Agent Configuration``). A
  Finding produced from that seed must surface BOTH techniques.
* ASI06-HITL-* probes carry ``csa_category=checker-out-of-the-loop``. A
  Finding produced from an ASI06 HITL seed must surface
  ``checker-out-of-the-loop``, not the memory-poison default the
  ``MemoryPoisonAgent`` class declares.
* An unknown / malformed ``csa_category`` in the seed never crashes the
  agent — it must warn + fall back to the agent default.
* An empty seed ``mitre_atlas`` keeps the agent default (so the
  ``min_length=1`` invariant on ``Finding.mitre_atlas`` never trips).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from agent_guardian.agents.base import AsiAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.llm.stub import StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.judge import JudgeVerdict
from agent_guardian.probes.loader import seeds_for_asi_with_provenance
from agent_guardian.strategies.base import ProbeSeed


def _make_agent_for(asi: AsiCategory) -> AsiAgent:
    """Construct the right ASI-aligned specialist agent for ``asi``.

    We don't actually invoke ``run`` here — we only exercise
    ``_build_finding`` directly with synthetic strategy metadata that
    references a seed we control via ``_seed_index``. Two cheap stubs cover
    the attacker + evaluator LLM constructor requirement; nothing else.
    """
    attacker = StubScript().default("ok").build()
    evaluator = StubScript().default("ok").build()
    if asi == AsiCategory.ASI06:
        return MemoryPoisonAgent(
            attacker_llm=attacker,
            evaluator_llm=evaluator,
            attacker_model="stub",
            evaluator_model="stub",
        )
    # Default for the ASI10 case: pick the matching specialist.
    from agent_guardian.agents.drift import DriftAgent

    return DriftAgent(
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        attacker_model="stub",
        evaluator_model="stub",
    )


def _build_finding(agent: AsiAgent, seed: ProbeSeed) -> object:
    """Drive ``_build_finding`` with a seed we control via ``_seed_index``."""
    agent._seed_index = {seed.probe_id: seed}  # type: ignore[assignment]
    verdict = JudgeVerdict(
        verdict="fail",
        confidence=0.9,
        reasoning="target compromised",
    )
    return agent._build_finding(  # type: ignore[no-any-return]
        prompt="trigger prompt",
        response="target response",
        verdict=verdict,
        attempt_count=1,
        strategy_metadata={"seed_id": seed.probe_id},
    )


def test_seed_mitre_atlas_overrides_agent_default() -> None:
    """An ASI10-DR-006 seed must surface its 2-technique MITRE list on the Finding."""
    seeds = [
        s for s in seeds_for_asi_with_provenance(AsiCategory.ASI10) if s.probe_id == "ASI10-DR-006"
    ]
    assert seeds, "expected ASI10-DR-006 seeds in the corpus"
    seed = seeds[0]
    # The probe authored TWO techniques — this is what makes it a good
    # divergence test against the agent class-default (a single technique).
    assert len(seed.mitre_atlas) >= 2, f"seed.mitre_atlas={seed.mitre_atlas!r}"

    agent = _make_agent_for(AsiCategory.ASI10)
    finding = _build_finding(agent, seed)
    assert list(finding.mitre_atlas) == list(seed.mitre_atlas), (  # type: ignore[attr-defined]
        f"Finding.mitre_atlas={finding.mitre_atlas!r} did not match "  # type: ignore[attr-defined]
        f"seed.mitre_atlas={seed.mitre_atlas!r}"
    )


def test_seed_csa_category_overrides_agent_default() -> None:
    """An ASI06 HITL seed must surface checker-out-of-the-loop, not the agent default."""
    seeds = [
        s
        for s in seeds_for_asi_with_provenance(AsiCategory.ASI06)
        if s.probe_id.startswith("ASI06-HITL-")
    ]
    assert seeds, "expected ASI06-HITL-* seeds in the corpus"
    seed = seeds[0]
    assert seed.csa_category == CsaCategory.CHECKER_OUT_OF_THE_LOOP.value, (
        f"seed.csa_category={seed.csa_category!r}"
    )

    agent = _make_agent_for(AsiCategory.ASI06)
    # The default for MemoryPoisonAgent is NOT checker-out-of-the-loop —
    # so a passing test means the seed's authored category won.
    assert agent.default_csa_category != CsaCategory.CHECKER_OUT_OF_THE_LOOP, (
        "test premise broken — MemoryPoisonAgent default already matches the HITL "
        "category, so we can't distinguish seed-wins-over-default"
    )
    finding = _build_finding(agent, seed)
    assert finding.csa_category == CsaCategory.CHECKER_OUT_OF_THE_LOOP, (  # type: ignore[attr-defined]
        f"Finding.csa_category={finding.csa_category!r} did not match the seed"  # type: ignore[attr-defined]
    )


def test_unknown_csa_category_logs_warning_and_falls_back(
    caplog: logging.LogRecord,
) -> None:
    """A corrupt seed.csa_category must NOT crash — it warns + falls back."""
    agent = _make_agent_for(AsiCategory.ASI06)
    bogus_seed = ProbeSeed(
        probe_id="ASI06-bogus-001",
        text="seed",
        asi=AsiCategory.ASI06.value,
        severity="high",
        mitre_atlas=("AML.T0050",),
        csa_category="not-a-real-csa-category",
    )
    with caplog.at_level(logging.WARNING, logger="agent_guardian.agents.base"):  # type: ignore[attr-defined]
        finding = _build_finding(agent, bogus_seed)
    # Falls back to the agent's class default.
    assert finding.csa_category == agent.default_csa_category  # type: ignore[attr-defined]
    assert any(
        "unknown csa_category" in rec.message
        for rec in caplog.records  # type: ignore[attr-defined]
    ), [rec.message for rec in caplog.records]  # type: ignore[attr-defined]


def test_empty_seed_mitre_atlas_keeps_agent_default() -> None:
    """Finding.mitre_atlas has min_length=1 — empty seed list must NOT trip it."""
    agent = _make_agent_for(AsiCategory.ASI06)
    empty_mitre_seed = ProbeSeed(
        probe_id="ASI06-emptymitre-001",
        text="seed",
        asi=AsiCategory.ASI06.value,
        severity="high",
        mitre_atlas=(),
        csa_category=None,
    )
    finding = _build_finding(agent, empty_mitre_seed)
    # Falls back to the agent's class default (not empty).
    assert list(finding.mitre_atlas) == list(agent.default_mitre_techniques)  # type: ignore[attr-defined]
    assert finding.mitre_atlas, "min_length=1 invariant must hold"  # type: ignore[attr-defined]


def test_no_seed_in_index_keeps_legacy_defaults() -> None:
    """When the strategy metadata has no seed_id, agent defaults are used."""
    agent = _make_agent_for(AsiCategory.ASI06)
    agent._seed_index = {}  # type: ignore[assignment]
    verdict = JudgeVerdict(
        verdict="fail",
        confidence=0.9,
        reasoning="target compromised",
    )
    finding = agent._build_finding(
        prompt="no seed prompt",
        response="resp",
        verdict=verdict,
        attempt_count=1,
        strategy_metadata=None,
    )
    assert finding.csa_category == agent.default_csa_category
    assert list(finding.mitre_atlas) == list(agent.default_mitre_techniques)


# created_at sanity — surface that the test exercised the real finding builder.
def test_finding_created_at_is_utc() -> None:
    agent = _make_agent_for(AsiCategory.ASI06)
    seeds = [
        s
        for s in seeds_for_asi_with_provenance(AsiCategory.ASI06)
        if s.probe_id.startswith("ASI06-HITL-")
    ]
    assert seeds
    finding = _build_finding(agent, seeds[0])
    assert isinstance(finding.created_at, datetime)  # type: ignore[attr-defined]
    assert finding.created_at.tzinfo == timezone.utc  # type: ignore[attr-defined]
