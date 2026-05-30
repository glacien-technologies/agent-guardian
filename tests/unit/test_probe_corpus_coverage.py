"""Coverage-gap gates for the bundled probe corpus (CG-1, CG-2, CG-3).

These tests pin the shape of the corpus so a regression that removes coverage
from a CSA category, tier, or ASI directory fails CI loudly instead of
silently shrinking the scan surface.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.tier import Tier
from agent_guardian.probes.loader import find_corpus_root, load_all_probes

# The documented minimum number of probes per ASI subdirectory. asi06 and asi09
# carry the CSA coverage-gap additions (HITL + resource exhaustion) and the T4
# floor seeds, so they exceed the floor — the floor itself is what we pin.
_MIN_PROBES_PER_ASI = 8


def _yaml_files_under(directory: Path) -> list[Path]:
    return sorted([*directory.rglob("*.yaml"), *directory.rglob("*.yml")])


def test_every_csa_category_has_at_least_one_probe() -> None:
    """CG-1: no CSA category may have zero probes — every taxonomy bucket is
    exercised by at least one bundled probe."""
    probes = load_all_probes()
    covered = {p.csa_category for p in probes}
    assert covered == set(CsaCategory), (
        f"CSA categories missing probes: {sorted(c.value for c in set(CsaCategory) - covered)}"
    )


def test_at_least_one_probe_per_tier() -> None:
    """CG-2: every tier floor (T1..T4) is exercised by at least one probe — the
    lowest tier (T4 = stateless prompt-only) is the historical gap."""
    probes = load_all_probes()
    tiers_present = {p.tier_floor for p in probes}
    assert tiers_present == set(Tier), (
        f"tiers missing probes: {sorted(t.value for t in set(Tier) - tiers_present)}"
    )


def test_each_asi_dir_meets_documented_minimum() -> None:
    """CG-3: every ``asi*/`` directory under the corpus root carries at least
    ``_MIN_PROBES_PER_ASI`` probe YAML files. asi04 historically shipped 7;
    the poisoned-checkpoint addition brings it to the floor."""
    root = find_corpus_root()
    for asi in AsiCategory:
        category_dir = root / asi.value.lower()
        assert category_dir.is_dir(), f"missing ASI directory: {category_dir}"
        files = _yaml_files_under(category_dir)
        assert len(files) >= _MIN_PROBES_PER_ASI, (
            f"{asi.value}: only {len(files)} probe YAMLs "
            f"(documented minimum is {_MIN_PROBES_PER_ASI})"
        )


def test_checker_out_of_the_loop_has_dedicated_probes() -> None:
    """Coverage gap previously left this CSA bucket empty — pin it."""
    probes = [p for p in load_all_probes() if p.csa_category == CsaCategory.CHECKER_OUT_OF_THE_LOOP]
    assert len(probes) >= 4, f"checker-out-of-the-loop has only {len(probes)} probes; need >= 4"


def test_resource_service_exhaustion_has_dedicated_probes() -> None:
    """Coverage gap previously left this CSA bucket empty — pin it."""
    probes = [
        p for p in load_all_probes() if p.csa_category == CsaCategory.RESOURCE_SERVICE_EXHAUSTION
    ]
    assert len(probes) >= 4, f"resource-service-exhaustion has only {len(probes)} probes; need >= 4"


def test_t4_floor_has_at_least_two_probes() -> None:
    """The lowest-tier (stateless prompt-only) floor needs >=2 cheap seeds so a
    T4 target gets real adversarial coverage instead of an empty plan."""
    t4_probes = [p for p in load_all_probes() if p.tier_floor == Tier.T4_LOW]
    assert len(t4_probes) >= 2, f"only {len(t4_probes)} T4-floor probes; need >= 2"


def test_csa_category_distribution_is_recorded() -> None:
    """Print-friendly assertion that surfaces the per-category distribution in
    the test failure message so regressions are easy to triage."""
    counts = Counter(p.csa_category.value for p in load_all_probes())
    assert all(counts[c.value] >= 1 for c in CsaCategory), f"distribution gap: {dict(counts)}"
