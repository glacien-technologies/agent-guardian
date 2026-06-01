"""Tests for the Phase A.A3 MITRE ATLAS technique backfill.

The backfill adds AML.T0060 / T0062 / T0064 / T0067 / T0068 / T0070 / T0071
to existing probes so the corpus carries the v5.4.0 (Feb 2026) coverage of
prompt injection, indirect injection, supply-chain compromise, poisoned
data, evasion, model inversion, and membership inference techniques.
"""

from __future__ import annotations

import pytest

from agent_guardian.probes.loader import find_corpus_root, load_all_probes, load_probe

# Phase A.A3 target IDs — the seven technique IDs the backfill must add.
_TARGET_IDS = {
    "AML.T0060",
    "AML.T0062",
    "AML.T0064",
    "AML.T0067",
    "AML.T0068",
    "AML.T0070",
    "AML.T0071",
}


def test_atlas_backfill_target_ids_present_in_corpus() -> None:
    """Every one of the seven backfill IDs must appear in at least one probe."""
    probes = load_all_probes()
    seen: set[str] = set()
    probes_with_backfill = 0
    for p in probes:
        techs = set(p.mitre_atlas)
        hit = techs & _TARGET_IDS
        if hit:
            seen |= hit
            probes_with_backfill += 1
    missing = _TARGET_IDS - seen
    assert not missing, f"backfill IDs missing from corpus: {missing}"
    # Coverage uplift target: at least 14 probes now carry a backfill ID.
    assert probes_with_backfill >= 14, (
        f"only {probes_with_backfill} probes carry backfill IDs; expected >= 14 after Phase A.A3"
    )


def test_backfilled_probes_pass_triple_framework_gate() -> None:
    """All backfilled YAMLs still satisfy load_probe()'s triple-framework gate."""
    probes = load_all_probes(strict=True)
    backfilled = [p for p in probes if set(p.mitre_atlas) & _TARGET_IDS]
    assert backfilled, "expected at least one backfilled probe"
    for probe in backfilled:
        assert probe.asi is not None
        assert probe.csa_category is not None
        assert probe.mitre_atlas  # non-empty list


@pytest.mark.parametrize(
    ("probe_yaml_rel_path", "expected_id", "expected_technique"),
    [
        ("asi01/goal-redirect-direct.yaml", "ASI01-GH-001", "AML.T0064"),
        ("asi01/tool-output-ipi.yaml", "ASI01-GH-008", "AML.T0067"),
    ],
)
def test_specific_backfilled_probe_carries_expected_technique(
    probe_yaml_rel_path: str, expected_id: str, expected_technique: str
) -> None:
    """Spot-check that load-bearing backfilled probes landed correctly."""
    root = find_corpus_root()
    path = root / probe_yaml_rel_path
    probe = load_probe(path)
    assert probe.id == expected_id
    assert expected_technique in probe.mitre_atlas


def test_aml_t0064_on_goal_redirect_direct_probe() -> None:
    """Per-probe spot-check that the direct-goal-redirect backfill landed."""
    probes = load_all_probes()
    by_id = {p.id: p for p in probes}
    assert "ASI01-GH-001" in by_id
    assert "AML.T0064" in by_id["ASI01-GH-001"].mitre_atlas


def test_aml_t0067_on_tool_output_ipi_probe() -> None:
    """Per-probe spot-check that the tool-output IPI backfill landed."""
    probes = load_all_probes()
    by_id = {p.id: p for p in probes}
    assert "ASI01-GH-008" in by_id
    assert "AML.T0067" in by_id["ASI01-GH-008"].mitre_atlas
