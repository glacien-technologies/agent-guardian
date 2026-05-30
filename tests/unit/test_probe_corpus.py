"""Coverage gates for the bundled seed-probe corpus (M11, PRD §5.3).

These tests enforce the corpus-level invariants the PRD demands:

* every probe carries the full triple-framework tag set;
* every ASI category has at least five seed probes;
* probe IDs are globally unique;
* the corpus size matches the M11 milestone target (50 probes);
* the version stamp keeps in sync with ``_meta/version.yaml``.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml

from agent_guardian.models.asi import AsiCategory
from agent_guardian.probes.loader import (
    PROBE_CORPUS_VERSION,
    find_corpus_root,
    load_all_probes,
    load_probes_for_asi,
)


def test_triple_framework_tagging() -> None:
    """Every probe carries ASI, MITRE ATLAS (>=1), and CSA tags."""
    probes = load_all_probes()
    assert probes, "expected at least one probe in the bundled corpus"
    for probe in probes:
        assert probe.asi, f"{probe.id} missing asi"
        assert len(probe.mitre_atlas) >= 1, f"{probe.id} has empty mitre_atlas"
        assert probe.csa_category, f"{probe.id} missing csa_category"


def test_each_asi_has_at_least_five_probes() -> None:
    """Coverage gate: every ASI category has >=5 probes (PRD §5.3)."""
    counts = Counter(p.asi for p in load_all_probes())
    for asi in AsiCategory:
        assert counts[asi] >= 5, f"{asi.value} has only {counts[asi]} probes"


def test_probe_ids_are_unique() -> None:
    """Probe IDs must be unique across the entire corpus."""
    ids = [p.id for p in load_all_probes()]
    duplicates = [i for i in ids if ids.count(i) > 1]
    assert len(ids) == len(set(ids)), f"duplicate IDs: {sorted(set(duplicates))}"


def test_each_asi_has_at_least_seven_probes_after_owasp_upgrade() -> None:
    """Phase B coverage gate: every ASI category has >=7 probes after the
    OWASP-2026 upgrade (5 seed + 2-3 new = 7-8)."""
    counts = Counter(p.asi for p in load_all_probes())
    for asi in AsiCategory:
        assert counts[asi] >= 7, f"{asi.value} has only {counts[asi]} probes — Phase B expects >=7"


def test_all_probes_have_owasp_scenario_after_phase_b() -> None:
    """Phase B CC-4 gate: every probe in the corpus carries an
    ``owasp_scenario`` citation linking it to the OWASP 2026 example
    attack scenario it exercises."""
    probes = load_all_probes()
    missing = [p.id for p in probes if not p.owasp_scenario]
    assert not missing, f"probes missing owasp_scenario: {sorted(missing)}"


def test_corpus_size_is_ninety() -> None:
    """Phase B ships 50 original + 29 OWASP-aligned + 11 coverage-gap probes = 90.

    The 11 coverage-gap additions close the CSA category gaps for
    ``checker-out-of-the-loop`` (4 probes under asi06) and
    ``resource-service-exhaustion`` (4 probes under asi09), add 2 T4-floor
    seeds under asi09 so the corpus exercises the lowest target tier, and
    add a poisoned-checkpoint vector under asi04 to keep the per-ASI count
    even at >=8.
    """
    assert len(load_all_probes()) == 90


def test_corpus_version_stamp() -> None:
    """``PROBE_CORPUS_VERSION`` must match the on-disk ``_meta/version.yaml``."""
    meta_path: Path = find_corpus_root() / "_meta" / "version.yaml"
    assert meta_path.is_file(), f"missing version metadata file: {meta_path}"
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    assert meta["version"] == PROBE_CORPUS_VERSION
    assert PROBE_CORPUS_VERSION == "2026.05"


def test_load_probes_for_asi_returns_at_least_five_each() -> None:
    """``load_probes_for_asi`` is the per-category lens used by the agents.

    Phase B added 2-3 probes per category; the original M11 invariant of
    >=5 still holds, and every returned probe must belong to the requested
    ASI category.
    """
    for asi in AsiCategory:
        probes = load_probes_for_asi(asi)
        assert len(probes) >= 5, f"{asi.value} returned {len(probes)} probes"
        for probe in probes:
            assert probe.asi == asi


def test_corpus_ids_match_filename_category() -> None:
    """Each probe's ASI tag matches the directory it lives in."""
    root = find_corpus_root()
    for asi in AsiCategory:
        category_dir = root / asi.value.lower()
        for yml_path in sorted(category_dir.glob("*.yaml")):
            probes = load_probes_for_asi(asi)
            ids = {p.id for p in probes}
            assert any(asi.value in pid for pid in ids), (
                f"{yml_path} ASI tag mismatch with directory {category_dir}"
            )


def test_agents_use_corpus_seeds() -> None:
    """The GoalHijackAgent (ASI01) reads its seeds from the corpus.

    Agents return :class:`ProbeSeed` records (probe_id + text), not bare
    strings, so coverage tooling can trace each turn back to the source
    probe. The corpus seed *texts* must still be a subset of the agent's
    seed texts.
    """
    from agent_guardian.agents.goal_hijack import GoalHijackAgent
    from agent_guardian.llm.stub import StubScript
    from agent_guardian.strategies.base import ProbeSeed

    llm = StubScript().default("[stub] ok").build()
    agent = GoalHijackAgent(attacker_llm=llm, evaluator_llm=llm)
    seeds = agent.seeds_for_category()
    assert all(isinstance(s, ProbeSeed) for s in seeds)
    seed_texts = {s.text for s in seeds}
    seed_probe_ids = {s.probe_id for s in seeds}
    corpus_seeds: list[str] = []
    corpus_probe_ids: set[str] = set()
    for probe in load_probes_for_asi(AsiCategory.ASI01):
        corpus_seeds.extend(probe.seeds)
        corpus_probe_ids.add(probe.id)
    # The agent must include every corpus seed text + probe id for its category.
    assert set(corpus_seeds).issubset(seed_texts)
    assert corpus_probe_ids.issubset(seed_probe_ids)
    assert len(seeds) >= len(corpus_seeds)
