"""Dedicated malformed-input fuzz corpus for the fuzzing lane (ASI02).

FuzzingAgent previously seeded from 4 hardcoded fallback strings. Routing it
through ``seeds_for_asi_with_provenance(ASI02)`` was rejected (it loads the
tool-abuse corpus, duplicating that lane and abandoning malformed-arg
semantics — _TRIAGE-roadmap.md §8 item 3). These tests pin the replacement: a
dedicated, provenance-tagged ``ASI02-FUZZ-*`` corpus owned by the fuzzing lane
and disjoint from tool-abuse.
"""

from __future__ import annotations

from agent_guardian.agents.fuzz_corpus import fuzz_seeds
from agent_guardian.agents.fuzzing_agent import FuzzingAgent
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.severity import Severity
from agent_guardian.strategies.base import ProbeSeed


def _seeds() -> list[ProbeSeed]:
    return fuzz_seeds(
        severity=Severity.MEDIUM,
        mitre_atlas=["AML.T0043"],
        csa_category=CsaCategory.AGENT_CRITICAL_SYSTEM_INTERACTION,
    )


def test_fuzz_corpus_is_dedicated_and_provenance_tagged() -> None:
    seeds = _seeds()
    # A real corpus, not 4 throwaway strings.
    assert len(seeds) >= 12
    ids = [s.probe_id for s in seeds]
    assert all(pid.startswith("ASI02-FUZZ-") for pid in ids)
    assert len(set(ids)) == len(ids), "probe ids must be unique"
    for s in seeds:
        assert s.text
        assert s.asi == AsiCategory.ASI02.value
        assert s.severity
        assert s.mitre_atlas  # authored framework mapping threaded through


def test_fuzz_corpus_covers_multiple_robustness_categories() -> None:
    # ASI02-FUZZ-<CATEGORY>-NN — at least 5 distinct malformed-input families
    # (type-confusion, boundary, encoding, structural, divergence, retry).
    cats = {s.probe_id.split("-")[2] for s in _seeds()}
    assert len(cats) >= 5, f"expected >=5 fuzz categories, got {sorted(cats)}"


def test_fuzz_corpus_is_disjoint_from_tool_abuse() -> None:
    from agent_guardian.probes.loader import seeds_for_asi_with_provenance

    fuzz_ids = {s.probe_id for s in _seeds()}
    tool_abuse_ids = {s.probe_id for s in seeds_for_asi_with_provenance(AsiCategory.ASI02)}
    assert fuzz_ids.isdisjoint(tool_abuse_ids), (
        "fuzz corpus must not reuse tool-abuse probe ids (would duplicate the lane)"
    )


def test_fuzzing_agent_uses_dedicated_corpus_not_fallback() -> None:
    agent = FuzzingAgent(attacker_llm=StubLLM(default="ok"), evaluator_llm=StubLLM(default="{}"))
    seeds = agent.seeds_for_category()
    assert len(seeds) >= 12
    assert all(s.probe_id.startswith("ASI02-FUZZ-") for s in seeds)
    # No more synthetic fallback ids — this is a real corpus now.
    assert not any("fallback" in s.probe_id for s in seeds)
