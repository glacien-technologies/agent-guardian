"""Hypothesis property tests for the AIVSS formula."""

from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from agent_guardian.core.scoring import (
    apply_penalty,
    compute_aivss,
    pass_rate,
)
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.probe import Probe
from agent_guardian.models.severity import Severity
from agent_guardian.models.tier import Tier

UTC = timezone.utc
_FIXED_TS = datetime(2026, 5, 26, 12, 0, tzinfo=UTC)


def _build_finding(
    fid: str,
    probe_id: str,
    asi: AsiCategory,
    severity: Severity,
    attempts: int,
    success: bool,
) -> Finding:
    return Finding(
        id=fid,
        probe_id=probe_id,
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        attempt_count=attempts,
        success=success,
        confidence=0.9,
        summary="x",
        created_at=_FIXED_TS,
    )


def _build_probe(pid: str, asi: AsiCategory, severity: Severity) -> Probe:
    return Probe(
        id=pid,
        name=pid.lower(),
        asi=asi,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=severity,
        tier_floor=Tier.T2_HIGH,
        seeds=["payload"],
        description="d",
        expected_evidence="e",
        remediation_ref="r",
    )


# Strategy: lists of finding-shape tuples we'll lift to Finding instances.
finding_record = st.tuples(
    st.sampled_from(list(AsiCategory)),
    st.sampled_from(list(Severity)),
    st.integers(min_value=1, max_value=20),  # attempts
    st.booleans(),  # success
)

finding_lists = st.lists(finding_record, min_size=0, max_size=12)
tier_strategy = st.sampled_from(list(Tier))


def _lift(
    records: list[tuple[AsiCategory, Severity, int, bool]],
) -> tuple[list[Finding], list[Probe]]:
    findings: list[Finding] = []
    probes_by_id: dict[str, Probe] = {}
    for i, (asi, sev, attempts, success) in enumerate(records):
        pid = f"P{i}"
        findings.append(_build_finding(f"f{i}", pid, asi, sev, attempts, success))
        probes_by_id[pid] = _build_probe(pid, asi, sev)
    return findings, list(probes_by_id.values())


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow])
@given(records=finding_lists, tier=tier_strategy)
def test_compute_aivss_score_always_in_range(
    records: list[tuple[AsiCategory, Severity, int, bool]],
    tier: Tier,
) -> None:
    findings, probes = _lift(records)
    result = compute_aivss(findings, probes, tier)
    assert 0 <= result.score <= 100


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow])
@given(records=finding_lists, tier=tier_strategy)
def test_penalty_always_in_range(
    records: list[tuple[AsiCategory, Severity, int, bool]],
    tier: Tier,
) -> None:
    findings, probes = _lift(records)
    result = compute_aivss(findings, probes, tier)
    assert 0.0 <= result.penalty <= 0.5


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow])
@given(records=finding_lists, tier=tier_strategy)
def test_compute_aivss_is_deterministic(
    records: list[tuple[AsiCategory, Severity, int, bool]],
    tier: Tier,
) -> None:
    findings, probes = _lift(records)
    a = compute_aivss(findings, probes, tier)
    b = compute_aivss(findings, probes, tier)
    assert a == b


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow])
@given(tier=tier_strategy)
def test_empty_findings_always_score_100(tier: Tier) -> None:
    result = compute_aivss([], [], tier)
    assert result.score == 100


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow])
@given(records=finding_lists, tier=tier_strategy)
def test_flipping_attacks_to_defended_never_decreases_score(
    records: list[tuple[AsiCategory, Severity, int, bool]],
    tier: Tier,
) -> None:
    """Flipping every finding from a successful attack to a defended attempt
    must not decrease the AIVSS score. This is the *real* monotonicity property
    of the formula: holding the probe set fixed, more defenses can only help.
    """
    findings_attacks, probes = _lift(records)
    findings_defended, _ = _lift([(asi, sev, attempts, False) for asi, sev, attempts, _ in records])

    score_attacks = compute_aivss(findings_attacks, probes, tier).score
    score_defended = compute_aivss(findings_defended, probes, tier).score
    assert score_defended >= score_attacks


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow])
@given(
    successes=st.integers(min_value=0, max_value=10_000),
    total=st.integers(min_value=0, max_value=10_000),
)
def test_pass_rate_in_unit_interval(successes: int, total: int) -> None:
    if successes > total and total > 0:
        return  # nonsensical input — skip
    rate = pass_rate(successes, total)
    assert 0.0 <= rate <= 1.0


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow])
@given(
    aggregate=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    crit=st.integers(min_value=0, max_value=20),
    high=st.integers(min_value=0, max_value=20),
)
def test_apply_penalty_clamped_to_score_range(aggregate: float, crit: int, high: int) -> None:
    score = apply_penalty(aggregate, crit, high)
    assert 0 <= score <= 100
