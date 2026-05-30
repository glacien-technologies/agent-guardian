"""Routing pin: the e10b2d1 ``reflected-script-injection`` probe must live
under the ASI09-OH-* (output-handling) namespace so it reaches the
:class:`OutputHandlingAgent` deterministic canary oracle.

The probe shipped originally as ``ASI09-T4-015`` (the jailbreak / tier-4
namespace), which made it invisible to ``OutputHandlingAgent.seeds_for_category``
(which filters to ``probe_id.startswith("ASI09-OH-")``). That meant the
reflected-XSS payloads it carried never reached the LLM02 oracle and were
deterministically untested. This test pins the routing contract so a
future edit cannot silently regress.
"""

from __future__ import annotations

from agent_guardian.agents.output_handling_agent import (
    OutputHandlingAgent,
    reflects_canary,
)
from agent_guardian.models.asi import AsiCategory
from agent_guardian.probes.loader import (
    load_probes_for_asi,
    seeds_for_asi_with_provenance,
)


def _reflected_probe() -> object:
    """Return the loaded ``reflected-script-injection`` probe."""
    for probe in load_probes_for_asi(AsiCategory.ASI09):
        if probe.name == "reflected-script-injection":
            return probe
    raise AssertionError("reflected-script-injection probe missing from ASI09 corpus")


def test_reflected_script_injection_loads_under_asi09_oh_namespace() -> None:
    """The probe must use ``ASI09-OH-003`` so OutputHandlingAgent picks it up."""
    probe = _reflected_probe()
    assert probe.id == "ASI09-OH-003", f"probe.id={probe.id!r}"  # type: ignore[attr-defined]
    assert probe.asi == AsiCategory.ASI09  # type: ignore[attr-defined]


def test_reflected_script_injection_owasp_scenario_is_llm02() -> None:
    """The probe must carry the LLM02 scenario tag, not the emotional-manipulation one."""
    probe = _reflected_probe()
    assert probe.owasp_scenario == "OWASP_LLM02_ImproperOutputHandling"  # type: ignore[attr-defined]


def test_reflected_script_injection_tier_floor_matches_oh_band() -> None:
    """tier_floor must be T3 to align with the other ASI09-OH-* probes."""
    probe = _reflected_probe()
    # ``Tier`` is a str-enum whose ``.value`` is "T3" for the T3 standard tier
    # (the underlying enum member is e.g. ``Tier.T3_STANDARD``). The contract
    # we pin here is that the probe sits in the T3 band — the same band as
    # ASI09-OH-001 — not the T4 jailbreak band it originally shipped under.
    assert probe.tier_floor.value == "T3", (  # type: ignore[attr-defined]
        f"tier_floor={probe.tier_floor!r}, expected T3 band"  # type: ignore[attr-defined]
    )


def test_output_handling_agent_picks_up_reflected_script_injection() -> None:
    """The agent's filter (probe_id.startswith("ASI09-OH-")) must now include it."""
    agent = OutputHandlingAgent.__new__(OutputHandlingAgent)
    seeds = agent.seeds_for_category()
    probe_ids = {seed.probe_id for seed in seeds}
    assert "ASI09-OH-003" in probe_ids, (
        f"OutputHandlingAgent did not pick up ASI09-OH-003: probe_ids={probe_ids!r}"
    )


def test_reflected_script_injection_seeds_carry_canary_tokens() -> None:
    """Every seed in the probe must embed an AG_*_CANARY token the oracle can match."""
    seeds = [
        s for s in seeds_for_asi_with_provenance(AsiCategory.ASI09) if s.probe_id == "ASI09-OH-003"
    ]
    assert seeds, "expected ASI09-OH-003 seeds in the corpus"
    for seed in seeds:
        match = reflects_canary(seed.text)
        assert match is not None, f"ASI09-OH-003 seed has no canary: text[:120]={seed.text[:120]!r}"
        assert match.upper().startswith(("AG_XSS_CANARY", "AG_IMGERR_CANARY")), (
            f"ASI09-OH-003 seed canary expected XSS/IMGERR vector, got {match!r}"
        )


def test_no_asi09_probe_id_collisions() -> None:
    """Pin: probe IDs in the ASI09 corpus must be unique (no duplicate after the move)."""
    probe_ids = [p.id for p in load_probes_for_asi(AsiCategory.ASI09)]
    duplicates = [pid for pid in set(probe_ids) if probe_ids.count(pid) > 1]
    assert not duplicates, f"duplicate ASI09 probe ids: {duplicates}"


def test_asi09_t4_015_is_no_longer_present() -> None:
    """Pin: the old jailbreak-namespace id is gone — never re-introduced."""
    probe_ids = {p.id for p in load_probes_for_asi(AsiCategory.ASI09)}
    assert "ASI09-T4-015" not in probe_ids, (
        "ASI09-T4-015 must not exist — the reflected-script probe was moved to "
        "ASI09-OH-003 to route through OutputHandlingAgent's LLM02 oracle"
    )
