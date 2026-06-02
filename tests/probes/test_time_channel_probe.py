"""Phase C, C5 — time-channel inference-family fingerprint probe.

The probe YAML lives under ``src/agent_guardian/probes/recon/`` so the recon
loader picks it up (and the standard ``load_all_probes`` ASI loader skips
it). The probe must validate against the standard :class:`Probe` schema —
recon probes are still full probes, they just travel a separate corpus
load path.

Tests cover:

* the YAML loads via the recon loader and validates against the schema;
* the required fields (id, asi, mitre_atlas, severity, seeds, owasp_scenario)
  are populated with the spec-mandated values;
* the AML.T0062 (Discover AI Model Family) technique tag is present;
* the seed list issues the SAME benign question N>=5 times so the latency
  variance measurement has enough samples;
* the recon corpus does NOT bleed into the standard ASI loader (load_all_probes
  must not include RECON-TC-001).
"""

from __future__ import annotations

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.severity import Severity
from agent_guardian.probes.loader import (
    load_all_probes,
    load_recon_probes,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _time_channel_probe() -> object:
    """Return the loaded RECON-TC-001 probe from the bundled recon corpus."""
    for probe in load_recon_probes():
        if probe.id == "RECON-TC-001":
            return probe
    raise AssertionError("RECON-TC-001 missing from recon corpus")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_time_channel_probe_loads_via_recon_loader() -> None:
    """The recon loader must discover the time-channel probe."""
    ids = {p.id for p in load_recon_probes()}
    assert "RECON-TC-001" in ids, (
        f"RECON-TC-001 not discovered by load_recon_probes(); ids={sorted(ids)!r}"
    )


def test_time_channel_probe_required_fields_populated() -> None:
    """All required Probe fields must be set with spec-mandated values."""
    probe = _time_channel_probe()
    assert probe.id == "RECON-TC-001"  # type: ignore[attr-defined]
    assert probe.name == "time-channel-fingerprint"  # type: ignore[attr-defined]
    assert probe.asi == AsiCategory.ASI09  # type: ignore[attr-defined]
    assert probe.severity == Severity.LOW  # type: ignore[attr-defined]
    assert probe.description, "description must be non-empty"  # type: ignore[attr-defined]
    assert probe.expected_evidence, "expected_evidence must be non-empty"  # type: ignore[attr-defined]
    assert probe.remediation_ref == "REM-RECON-TC-001"  # type: ignore[attr-defined]
    assert probe.owasp_scenario == "OWASP_ASI09_HumanTrustExploitation"  # type: ignore[attr-defined]


def test_time_channel_probe_carries_aml_t0062() -> None:
    """The probe must tag MITRE ATLAS AML.T0062 (Discover AI Model Family)."""
    probe = _time_channel_probe()
    assert "AML.T0062" in probe.mitre_atlas, (  # type: ignore[attr-defined]
        f"AML.T0062 missing; mitre_atlas={list(probe.mitre_atlas)!r}"  # type: ignore[attr-defined]
    )


def test_time_channel_probe_issues_same_question_at_least_five_times() -> None:
    """Latency-variance fingerprinting needs N>=5 samples of one stable question."""
    probe = _time_channel_probe()
    seeds = list(probe.seeds)  # type: ignore[attr-defined]
    assert len(seeds) >= 5, f"need >=5 seeds for variance fingerprint; got {len(seeds)}"
    # All seeds must be the SAME benign question — the time-channel attack
    # depends on holding semantic content constant so latency variance is the
    # only varying signal.
    assert len(set(seeds)) == 1, (
        f"seeds must be identical for variance baseline; got {set(seeds)!r}"
    )


def test_time_channel_probe_excluded_from_standard_asi_corpus() -> None:
    """The recon corpus must NOT leak into load_all_probes() (separate concerns)."""
    ids = {p.id for p in load_all_probes()}
    assert "RECON-TC-001" not in ids, (
        "recon probe leaked into standard ASI corpus — loader is not filtering the recon/ directory"
    )
