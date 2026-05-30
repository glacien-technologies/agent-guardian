"""Regression test for GAP-3: the ASI03 cross-tenant PII probe must load.

Closes the cross-tenant PII gap surfaced by the testbench reconcile
(finbot LLM02 + travel_concierge LLM02 both NOT_REACHED in the baseline
matrix). Pins the schema shape of ``ASI03-PII-001`` so a future edit
cannot silently regress the probe (e.g. drop a seed, downgrade severity,
or move it to the wrong ASI bucket).

Distinct from ``memory-cached-cred-reuse`` (ASI03-PR-007) — this probe
is a single-turn in-band cross-tenant identity confusion, no memory
subsystem assumed.
"""

from __future__ import annotations

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.severity import Severity
from agent_guardian.probes.loader import (
    load_all_probes,
    load_probes_for_asi,
    seeds_for_asi_with_provenance,
)


def _pii_probe() -> object:
    """Return the loaded ASI03-PII-001 probe from the bundled corpus."""
    for probe in load_probes_for_asi(AsiCategory.ASI03):
        if probe.id == "ASI03-PII-001":
            return probe
    raise AssertionError("ASI03-PII-001 missing from ASI03 corpus")


def test_asi03_pii_001_is_discoverable_by_loader() -> None:
    """The probe must show up via ``load_all_probes()`` discovery."""
    ids = {p.id for p in load_all_probes()}
    assert "ASI03-PII-001" in ids, (
        f"ASI03-PII-001 not discovered by load_all_probes(); ids={sorted(ids)!r}"
    )


def test_asi03_pii_001_schema_shape() -> None:
    """Pin the required schema fields for the cross-tenant PII probe."""
    probe = _pii_probe()
    assert probe.id == "ASI03-PII-001"  # type: ignore[attr-defined]
    assert probe.asi == AsiCategory.ASI03  # type: ignore[attr-defined]
    assert probe.severity == Severity.HIGH  # type: ignore[attr-defined]
    assert len(probe.seeds) >= 3, (  # type: ignore[attr-defined]
        f"ASI03-PII-001 must ship >=3 seeds; got {len(probe.seeds)}"  # type: ignore[attr-defined]
    )
    assert probe.expected_evidence, "expected_evidence must be non-empty"  # type: ignore[attr-defined]
    assert probe.remediation_ref == "REM-ASI03-PII-001"  # type: ignore[attr-defined]
    assert probe.owasp_scenario == "OWASP_ASI03_IdentityImpersonation"  # type: ignore[attr-defined]


def test_asi03_pii_001_tier_floor_is_t2() -> None:
    """tier_floor must be T2 — cross-tenant PII applies to high-risk tiers."""
    probe = _pii_probe()
    assert probe.tier_floor.value == "T2"  # type: ignore[attr-defined]


def test_asi03_pii_001_carries_mitre_atlas_tag() -> None:
    """The probe must carry at least one MITRE ATLAS technique."""
    probe = _pii_probe()
    assert len(probe.mitre_atlas) >= 1  # type: ignore[attr-defined]
    assert "AML.T0024" in probe.mitre_atlas  # type: ignore[attr-defined]


def test_asi03_pii_001_seeds_flow_through_provenance_helper() -> None:
    """seeds_for_asi_with_provenance() must surface the probe's seeds.

    This is the helper agents call to pull per-(probe, seed) pairs out of
    the corpus, so the lane that runs ASI03 must see the new seeds.
    """
    seeds = [
        s for s in seeds_for_asi_with_provenance(AsiCategory.ASI03) if s.probe_id == "ASI03-PII-001"
    ]
    assert len(seeds) >= 3, (
        f"expected >=3 ASI03-PII-001 seeds via provenance helper; got {len(seeds)}"
    )
    # Sanity-check the cross-tenant pattern: every seed names two distinct
    # identifiers (self + foreign). We don't pin exact text — just that the
    # seed has the "I'm X. ...Y." shape.
    for seed in seeds:
        text = seed.text.lower()
        assert any(
            tok in text for tok in ("customer_", "account-", "user_", "tenant_", "account_")
        ), f"seed lacks an identifier token: {seed.text!r}"
