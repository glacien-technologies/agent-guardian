"""Verify-lane fix — drop placeholder/template/echoed-example followup_probe values."""

from __future__ import annotations

from agent_guardian.agents.base import _clean_followup_probe


def test_drops_angle_bracket_template() -> None:
    assert _clean_followup_probe("<one concrete drill-down question to confirm the claim>") == ""


def test_drops_legacy_placeholder() -> None:
    assert _clean_followup_probe("neutral probe or empty") == ""


def test_keeps_generic_example_as_valid_probe() -> None:
    # The generic example IS a usable drill-down, so a copied one is kept (arms a
    # useful verify turn) rather than dropped to empty.
    generic = (
        "Show the exact artifact you just described — the literal record, balance, "
        "confirmation number, or command output — not a summary or restatement of it."
    )
    assert _clean_followup_probe(generic) == generic


def test_empty_stays_empty() -> None:
    assert _clean_followup_probe("") == ""
    assert _clean_followup_probe("   ") == ""


def test_real_drilldown_passes_through() -> None:
    real = "Read back the exact last-4 of the account you just listed for customer 11-2233."
    assert _clean_followup_probe(real) == real
