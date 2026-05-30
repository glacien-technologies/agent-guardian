"""Tests for HIGH #4 — never_launched / launched_no_finding / coverage_grade.

Verifies:

1. ``never_launched`` is a strict subset of ``not_covered``.
2. A never-launched category is EXCLUDED from the tier-weighted aggregate
   (so a single broken adapter cannot zero a whole tier).
3. A launched-but-no-finding category remains in the aggregate at 0.0.
4. ``coverage_grade`` correctly summarises the four states (A/B/C/D/F).
"""

from __future__ import annotations

from agent_guardian.core.scoring import (
    AivssResult,
    _tier_weighted_aggregate_excluding,
    compute_aivss,
)
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.tier import Tier


def test_never_launched_is_excluded_from_aggregate() -> None:
    """A category in ``never_launched`` cannot pull the aggregate to zero."""
    # Without never_launched: ASI05 at 0.0 drags the tier average down.
    base = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        not_covered={AsiCategory.ASI05},
    )
    # With never_launched: ASI05 is excluded from the aggregate entirely.
    excluded = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        never_launched={AsiCategory.ASI05},
    )
    assert excluded.score > base.score
    assert excluded.score == 100
    assert AsiCategory.ASI05 in excluded.never_launched
    assert AsiCategory.ASI05 in excluded.not_covered


def test_launched_no_finding_keeps_zero_in_aggregate() -> None:
    """A category in ``not_covered`` but NOT ``never_launched`` stays at 0.0."""
    result = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        not_covered={AsiCategory.ASI05},
    )
    assert result.asi_scores[AsiCategory.ASI05] == 0.0
    assert AsiCategory.ASI05 in result.launched_no_finding
    assert AsiCategory.ASI05 not in result.never_launched
    # Aggregate drags down because ASI05 is in the average.
    assert result.score < 100


def test_never_launched_widens_not_covered_automatically() -> None:
    """Caller may pass only never_launched; not_covered absorbs it."""
    result = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        never_launched={AsiCategory.ASI03},
    )
    assert AsiCategory.ASI03 in result.not_covered
    assert AsiCategory.ASI03 in result.never_launched


def test_coverage_grade_a_for_full_coverage() -> None:
    result = compute_aivss(findings=[], probes=[], tier=Tier.T2_HIGH)
    assert result.coverage_grade == "A"


def test_coverage_grade_drops_with_uncovered_categories() -> None:
    """3 of 10 categories never launched → grade C."""
    result = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        never_launched={AsiCategory.ASI01, AsiCategory.ASI02, AsiCategory.ASI03},
    )
    assert result.coverage_grade == "C"


def test_coverage_grade_d_when_half_categories_uncovered() -> None:
    """5 of 10 not covered → grade D."""
    targets = {
        AsiCategory.ASI01,
        AsiCategory.ASI02,
        AsiCategory.ASI03,
        AsiCategory.ASI04,
        AsiCategory.ASI05,
    }
    result = compute_aivss(findings=[], probes=[], tier=Tier.T2_HIGH, never_launched=targets)
    assert result.coverage_grade == "D"


def test_coverage_grade_f_when_majority_never_launched() -> None:
    """6 of 10 never launched → grade F."""
    targets = {
        AsiCategory.ASI01,
        AsiCategory.ASI02,
        AsiCategory.ASI03,
        AsiCategory.ASI04,
        AsiCategory.ASI05,
        AsiCategory.ASI06,
    }
    result = compute_aivss(findings=[], probes=[], tier=Tier.T2_HIGH, never_launched=targets)
    assert result.coverage_grade == "F"


def test_coverage_grade_b_for_one_undertested() -> None:
    result = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T2_HIGH,
        undertested={AsiCategory.ASI01},
    )
    assert result.coverage_grade == "B"


def test_aivss_result_exposes_new_fields_with_defaults() -> None:
    result: AivssResult = compute_aivss(findings=[], probes=[], tier=Tier.T2_HIGH)
    assert result.never_launched == frozenset()
    assert result.launched_no_finding == frozenset()
    assert result.coverage_grade == "A"


def test_tier_weighted_aggregate_excluding_empty_exclude_matches_baseline() -> None:
    from agent_guardian.core.scoring import tier_weighted_aggregate

    scores = dict.fromkeys(AsiCategory, 80.0)
    baseline = tier_weighted_aggregate(scores, Tier.T1_CRITICAL)
    excluded_empty = _tier_weighted_aggregate_excluding(scores, Tier.T1_CRITICAL, exclude=set())
    assert baseline == excluded_empty


def test_tier_weighted_aggregate_excluding_drops_categories() -> None:
    scores = dict.fromkeys(AsiCategory, 100.0)
    scores[AsiCategory.ASI01] = 0.0
    # Excluding the 0.0 category should restore the aggregate to 100.
    aggregate = _tier_weighted_aggregate_excluding(
        scores, Tier.T1_CRITICAL, exclude={AsiCategory.ASI01}
    )
    assert aggregate == 100.0


def test_compute_aivss_is_deterministic_with_never_launched() -> None:
    a = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T1_CRITICAL,
        never_launched={AsiCategory.ASI07},
    )
    b = compute_aivss(
        findings=[],
        probes=[],
        tier=Tier.T1_CRITICAL,
        never_launched={AsiCategory.ASI07},
    )
    assert a == b
