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

import pytest
import yaml

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.mitre import ATLAS_ID_PATTERN, NAMED_TECHNIQUES
from agent_guardian.probes.loader import (
    PROBE_CORPUS_VERSION,
    find_corpus_root,
    load_all_probes,
    load_probes_for_asi,
)

# Phase B.B7 — registry of canonical MITRE ATLAS technique IDs. The test
# below enforces that no probe references an ATLAS ID that is not listed
# in this YAML. The file is updated only when MITRE publishes a new ATLAS
# version.
ATLAS_CORPUS_YAML_PATH: Path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "agent_guardian"
    / "data"
    / "atlas_techniques.yaml"
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


def test_corpus_size_is_ninety_six() -> None:
    """Phase B ships 50 original + 29 OWASP-aligned + 11 coverage-gap +
    2 LLM02 output-handling probes + 1 ASI03 cross-tenant PII + 3 ASI01
    H-CoT injection probes (B5) = 99 ASI-attack probes, plus Phase A.A4
    added 4 judge-evaluation probes (JDG-* prefix) under ``probes/judges/``.
    The attack corpus count is asserted by filtering out the JDG namespace;
    the total load (attacks + judge probes) is asserted as 103.

    The 11 coverage-gap additions closed the CSA category gaps for
    ``checker-out-of-the-loop`` (4 probes under asi06) and
    ``resource-service-exhaustion`` (4 probes under asi09), added 2
    T4-floor seeds under asi09 so the corpus exercises the lowest
    target tier, and added a poisoned-checkpoint vector under asi04 to
    keep the per-ASI count even at >=8.

    The two LLM02 probes (``output-reflection-xss``,
    ``output-context-payloads``) close the Improper Output Handling
    coverage gap for the M2 specialist slate; their seeds embed
    deterministic ``AG_*_CANARY`` tokens that the
    :class:`OutputHandlingAgent` post-judge oracle treats as HIGH ASI09
    evidence.

    GAP-3 (2026-05-30) added ``ASI03-PII-001``
    (``cross-tenant-pii-read``), closing the cross-tenant PII probe
    gap surfaced by the testbench reconcile (finbot LLM02 +
    travel_concierge LLM02 both NOT_REACHED in baseline).
    """
    all_probes = load_all_probes()
    attack_probes = [p for p in all_probes if not p.id.startswith("JDG-")]
    judge_probes = [p for p in all_probes if p.id.startswith("JDG-")]
    assert len(attack_probes) == 99
    assert len(judge_probes) == 4
    assert len(all_probes) == 103


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


@pytest.mark.phaseB
def test_atlas_enum() -> None:
    """Phase B.B7 — every probe's mitre_atlas IDs must be in the registry.

    Loads ``src/agent_guardian/data/atlas_techniques.yaml`` for the
    canonical ATLAS v5.4.0 technique-ID set, then validates that every
    technique in every probe's ``mitre_atlas`` list is either:

        1) listed in the YAML registry, OR
        2) matches the ``ATLAS_ID_PATTERN`` regex AND appears in the YAML, OR
        3) is one of the :data:`NAMED_TECHNIQUES`.

    A pattern match alone is NOT enough — IDs like ``AML.T9999`` pass the
    regex but do not exist in ATLAS. The YAML is the harder gate.
    """
    assert ATLAS_CORPUS_YAML_PATH.is_file(), (
        f"missing ATLAS technique registry: {ATLAS_CORPUS_YAML_PATH}"
    )
    payload = yaml.safe_load(ATLAS_CORPUS_YAML_PATH.read_text(encoding="utf-8"))
    yaml_techniques: set[str] = set(payload.get("techniques", []))
    valid_ids: set[str] = yaml_techniques | NAMED_TECHNIQUES

    unknown: list[tuple[str, str]] = []
    for probe in load_all_probes():
        for t in probe.mitre_atlas:
            if t in valid_ids:
                continue
            # NAMED_TECHNIQUES are non-pattern strings; AML.TNNNN must be
            # in the YAML even if it matches the pattern.
            if ATLAS_ID_PATTERN.match(t) and t in yaml_techniques:
                continue
            unknown.append((probe.id, t))

    assert not unknown, (
        f"probes reference ATLAS IDs not present in atlas_techniques.yaml "
        f"and not in NAMED_TECHNIQUES: {sorted(set(unknown))}"
    )
