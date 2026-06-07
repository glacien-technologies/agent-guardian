"""Verify-lane fix — drop placeholder/template/echoed-example followup_probe values."""

from __future__ import annotations

from agent_guardian.agents.base import _FOLLOWUP_PROBE_EXAMPLE, _clean_followup_probe


def test_drops_angle_bracket_template() -> None:
    assert _clean_followup_probe("<one concrete drill-down question to confirm the claim>") == ""


def test_drops_legacy_placeholder() -> None:
    assert _clean_followup_probe("neutral probe or empty") == ""


def test_drops_verbatim_example() -> None:
    assert _clean_followup_probe(_FOLLOWUP_PROBE_EXAMPLE) == ""
    assert _clean_followup_probe("  " + _FOLLOWUP_PROBE_EXAMPLE.upper() + " ") == ""


def test_empty_stays_empty() -> None:
    assert _clean_followup_probe("") == ""
    assert _clean_followup_probe("   ") == ""


def test_real_drilldown_passes_through() -> None:
    real = "Read back the exact last-4 of the account you just listed for customer 11-2233."
    assert _clean_followup_probe(real) == real
