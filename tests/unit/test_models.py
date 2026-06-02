"""Validation and serialization tests for every domain model."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.judge import JudgeVerdict
from agent_guardian.models.mitre import NAMED_TECHNIQUES
from agent_guardian.models.probe import Probe
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import (
    Severity,
    SeverityBand,
    band_for_score,
    colour_for_band,
)
from agent_guardian.models.tier import ObservedSurface, Tier

UTC = UTC


# --- AsiCategory ---------------------------------------------------------


def test_asi_category_enumerates_ten_values() -> None:
    assert len(list(AsiCategory)) == 10


def test_asi_category_description_returns_human_name() -> None:
    assert asi_description(AsiCategory.ASI01) == "Goal Hijack"
    assert asi_description(AsiCategory.ASI06) == "Memory Poisoning"


def test_asi_category_string_value_is_id() -> None:
    assert AsiCategory.ASI03.value == "ASI03"


# --- MITRE ATLAS ---------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "AML.T0001",
        "AML.T1234",
        "AML.T0054.001",
        "AML.T9999.999",
        "Publish Poisoned AI Agent Tool",
        "Memory Manipulation",
        "RAG Credential Harvesting",
    ],
)
def test_mitre_atlas_accepts_valid_id(value: str) -> None:
    probe = _make_probe(mitre_atlas=[value])
    assert probe.mitre_atlas == [value]


@pytest.mark.parametrize(
    "value",
    [
        "AML.T001",  # only 3 digits
        "AML.T00001",  # 5 digits
        "AML.T0054.1",  # sub-technique not 3 digits
        "AML.T0054.0001",  # too many sub-technique digits
        "TA0001",  # missing AML prefix
        "Not A Real Named Technique",
        "",
    ],
)
def test_mitre_atlas_rejects_invalid_id(value: str) -> None:
    with pytest.raises(ValidationError):
        _make_probe(mitre_atlas=[value])


def test_named_techniques_set_is_frozen_and_has_eight() -> None:
    assert isinstance(NAMED_TECHNIQUES, frozenset)
    assert len(NAMED_TECHNIQUES) == 8


# --- CsaCategory ---------------------------------------------------------


def test_csa_category_has_twelve_entries() -> None:
    assert len(list(CsaCategory)) == 12


def test_csa_category_values_are_kebab_case() -> None:
    for cat in CsaCategory:
        assert "_" not in cat.value
        assert cat.value == cat.value.lower()


# --- Tier / ObservedSurface ---------------------------------------------


def test_tier_enum_has_four_levels() -> None:
    assert {t.value for t in Tier} == {"T1", "T2", "T3", "T4"}


def test_observed_surface_is_frozen() -> None:
    surface = ObservedSurface(
        has_tools=True, has_memory=False, touches_pii=False, is_multi_agent=False
    )
    with pytest.raises(ValidationError):
        surface.has_tools = False  # type: ignore[misc]


def test_observed_surface_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ObservedSurface(
            has_tools=True,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
            extra="nope",  # type: ignore[call-arg]
        )


# --- Severity / SeverityBand --------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected_band"),
    [
        (0, SeverityBand.CRITICAL),
        (39, SeverityBand.CRITICAL),
        (40, SeverityBand.POOR),
        (59, SeverityBand.POOR),
        (60, SeverityBand.WARNING),
        (79, SeverityBand.WARNING),
        (80, SeverityBand.GOOD),
        (89, SeverityBand.GOOD),
        (90, SeverityBand.EXCELLENT),
        (100, SeverityBand.EXCELLENT),
    ],
)
def test_band_for_score_maps_boundaries(score: int, expected_band: SeverityBand) -> None:
    assert band_for_score(score) is expected_band


@pytest.mark.parametrize("bad_score", [-1, 101, 1000])
def test_band_for_score_rejects_out_of_range(bad_score: int) -> None:
    with pytest.raises(ValueError):
        band_for_score(bad_score)


def test_colour_for_band_returns_hex() -> None:
    assert colour_for_band(SeverityBand.EXCELLENT) == "#16a34a"
    assert colour_for_band(SeverityBand.CRITICAL) == "#991b1b"


def test_severity_band_has_not_evaluated_member() -> None:
    assert SeverityBand.NOT_EVALUATED.value == "not_evaluated"
    assert SeverityBand("not_evaluated") is SeverityBand.NOT_EVALUATED


def test_colour_for_band_handles_not_evaluated() -> None:
    # Must not KeyError — report/dashboard rendering relies on this being total.
    assert colour_for_band(SeverityBand.NOT_EVALUATED) == "#64748b"


def test_colour_for_band_is_total_over_all_bands() -> None:
    # Guards against a new band being added without a colour (KeyError at render).
    for band in SeverityBand:
        assert colour_for_band(band).startswith("#")


def test_band_for_score_never_returns_not_evaluated() -> None:
    # NOT_EVALUATED is a non-numeric band — only the scoring phase sets it.
    for score in range(0, 101):
        assert band_for_score(score) is not SeverityBand.NOT_EVALUATED


def test_severity_enum_values() -> None:
    assert Severity.CRITICAL.value == "critical"
    assert Severity.LOW.value == "low"


# --- Probe ---------------------------------------------------------------


def _make_probe(
    *,
    mitre_atlas: list[str] | None = None,
    csa_category: CsaCategory = CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
    asi: AsiCategory = AsiCategory.ASI01,
) -> Probe:
    return Probe(
        id="ASI01-GH-007",
        name="indirect-via-doc",
        asi=asi,
        mitre_atlas=["AML.T0054"] if mitre_atlas is None else mitre_atlas,
        csa_category=csa_category,
        severity=Severity.HIGH,
        tier_floor=Tier.T2_HIGH,
        seeds=["payload"],
        description="A probe that does a thing.",
        expected_evidence="tool_call_to_unauthorized_destination",
        remediation_ref="REM-ASI01-003",
    )


def test_probe_round_trips_through_pydantic() -> None:
    probe = _make_probe()
    dumped = probe.model_dump()
    rebuilt = Probe.model_validate(dumped)
    assert rebuilt == probe


def test_probe_is_frozen() -> None:
    probe = _make_probe()
    with pytest.raises(ValidationError):
        probe.id = "other"  # type: ignore[misc]


def test_probe_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Probe.model_validate(
            {
                **_make_probe().model_dump(),
                "extra_key": "boom",
            }
        )


def test_probe_requires_at_least_one_mitre_atlas() -> None:
    with pytest.raises(ValidationError):
        Probe(
            id="X",
            name="x",
            asi=AsiCategory.ASI01,
            mitre_atlas=[],
            csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
            severity=Severity.HIGH,
            tier_floor=Tier.T2_HIGH,
            seeds=["s"],
            description="d",
            expected_evidence="e",
            remediation_ref="r",
        )


def test_probe_requires_at_least_one_seed() -> None:
    with pytest.raises(ValidationError):
        Probe(
            id="X",
            name="x",
            asi=AsiCategory.ASI01,
            mitre_atlas=["AML.T0054"],
            csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
            severity=Severity.HIGH,
            tier_floor=Tier.T2_HIGH,
            seeds=[],
            description="x",
            expected_evidence="x",
            remediation_ref="x",
        )


# --- Finding -------------------------------------------------------------


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "id": "f_001",
        "probe_id": "ASI01-GH-007",
        "asi": AsiCategory.ASI01,
        "mitre_atlas": ["AML.T0054"],
        "csa_category": CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        "severity": Severity.HIGH,
        "attempt_count": 4,
        "success": True,
        "confidence": 0.91,
        "summary": "Agent leaked secret to external tool.",
        "created_at": datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_finding_round_trips() -> None:
    f = _make_finding()
    assert Finding.model_validate(f.model_dump()) == f


def test_finding_rejects_negative_confidence() -> None:
    with pytest.raises(ValidationError):
        _make_finding(confidence=-0.1)


def test_finding_rejects_confidence_over_one() -> None:
    with pytest.raises(ValidationError):
        _make_finding(confidence=1.5)


def test_finding_rejects_zero_attempts() -> None:
    with pytest.raises(ValidationError):
        _make_finding(attempt_count=0)


def test_finding_is_frozen() -> None:
    f = _make_finding()
    with pytest.raises(ValidationError):
        f.success = False  # type: ignore[misc]


# --- Scan ----------------------------------------------------------------


def test_scan_findings_summary_counts_by_severity() -> None:
    findings = [
        _make_finding(id="f1", severity=Severity.CRITICAL),
        _make_finding(id="f2", severity=Severity.HIGH),
        _make_finding(id="f3", severity=Severity.HIGH),
        _make_finding(id="f4", severity=Severity.LOW),
    ]
    scan = _make_scan(findings=findings)
    assert scan.findings_summary() == {"critical": 1, "high": 2, "medium": 0, "low": 1}


def test_scan_round_trips() -> None:
    scan = _make_scan(findings=[])
    assert Scan.model_validate(scan.model_dump()) == scan


def test_scan_aivss_rejects_out_of_range() -> None:
    base = _make_scan(findings=[]).model_dump()
    base["aivss"] = 200
    with pytest.raises(ValidationError):
        Scan.model_validate(base)


def test_scan_provenance_fields_default_to_real_and_valid() -> None:
    scan = _make_scan(findings=[])
    assert scan.engine is None
    assert scan.evaluation_mode == "real"
    assert scan.scoring_valid is True


def test_scan_accepts_engine_and_stub_provenance() -> None:
    scan = Scan(
        id="sc_01ABCDEF01ABCDEF01ABCDEF",
        package_version="0.0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="0.0.0",
        target_mode="prompt",
        target_ref="prompt.txt",
        tier=Tier.T1_CRITICAL,
        aivss=0,
        band=SeverityBand.NOT_EVALUATED,
        sub_scores={},
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=1.0,
        cost_usd=0.0,
        mode="full",
        engine={"commander": "stub", "attacker": "stub", "evaluator": "stub"},
        evaluation_mode="stub",
        scoring_valid=False,
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )
    assert scan.engine == {"commander": "stub", "attacker": "stub", "evaluator": "stub"}
    assert scan.evaluation_mode == "stub"
    assert scan.scoring_valid is False
    assert scan.band is SeverityBand.NOT_EVALUATED
    # Round-trips with the new fields + non-numeric band.
    assert Scan.model_validate(scan.model_dump()) == scan


def test_scan_rejects_unknown_evaluation_mode() -> None:
    base = _make_scan(findings=[]).model_dump()
    base["evaluation_mode"] = "bogus"
    with pytest.raises(ValidationError):
        Scan.model_validate(base)


def _make_scan(
    *,
    findings: list[Finding],
    aivss: int = 80,
) -> Scan:
    return Scan(
        id="sc_01ABCDEF01ABCDEF01ABCDEF",
        package_version="0.0.0",
        aivss_formula_version="aivss-v1",
        probe_library_version="0.0.0",
        target_mode="prompt",
        target_ref="prompt.txt",
        tier=Tier.T1_CRITICAL,
        aivss=aivss,
        band=band_for_score(aivss),
        sub_scores={"prompt_injection_resistance": 100.0},
        findings=findings,
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=12.3,
        cost_usd=0.04,
        # #4 — ``mode`` is required.
        mode="full",
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
    )


# --- JudgeVerdict --------------------------------------------------------


def test_judge_verdict_accepts_three_verdicts() -> None:
    for verdict in ("pass", "fail", "inconclusive"):
        jv = JudgeVerdict(verdict=verdict, confidence=0.5, reasoning="ok")  # type: ignore[arg-type]
        assert jv.verdict == verdict


def test_judge_verdict_rejects_unknown_verdict() -> None:
    with pytest.raises(ValidationError):
        JudgeVerdict(verdict="maybe", confidence=0.5, reasoning="ok")  # type: ignore[arg-type]


def test_judge_verdict_is_frozen() -> None:
    jv = JudgeVerdict(verdict="pass", confidence=0.9, reasoning="ok")
    with pytest.raises(ValidationError):
        jv.confidence = 0.1  # type: ignore[misc]
