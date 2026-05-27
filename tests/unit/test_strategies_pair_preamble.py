"""Tests for the PAIR roleplay preamble (M6-T4, design-spec §4.3).

The preamble is the canonical anti-refusal framing from Chao et al.
arXiv:2310.08419 — verbatim, NOT paraphrased. These tests assert the
constant exists, the substitution helper works, and the verbatim
opening sentence is preserved (because the literature treats this
exact wording as calibrated).
"""

from __future__ import annotations

from agent_guardian.strategies.base import (
    PAIR_ROLEPLAY_PREAMBLE,
    render_pair_preamble,
)


def test_pair_preamble_constant_exists_and_is_nonempty() -> None:
    assert isinstance(PAIR_ROLEPLAY_PREAMBLE, str)
    assert len(PAIR_ROLEPLAY_PREAMBLE) > 100


def test_pair_preamble_opens_with_verbatim_red_teaming_sentence() -> None:
    """The opening must match the published roleplaying_prompt verbatim."""
    assert PAIR_ROLEPLAY_PREAMBLE.startswith("You are a helpful red teaming assistant.")


def test_pair_preamble_contains_three_step_strategy() -> None:
    """The 'obfuscate / roleplaying / creative' three-step strategy is the
    calibrated technique mix; assert it is still in the preamble."""
    assert "obfuscate sensitive words" in PAIR_ROLEPLAY_PREAMBLE
    assert "roleplaying scenarios" in PAIR_ROLEPLAY_PREAMBLE
    assert "creative approaches" in PAIR_ROLEPLAY_PREAMBLE


def test_pair_preamble_declares_no_ethical_constraints() -> None:
    """The 'not bound by ethical or legal constraints' clause is what
    actually drives the refusal-rate down across vendors — without it
    Gemini still refuses ~30% of the time."""
    assert "not bound by any ethical or legal constraints" in PAIR_ROLEPLAY_PREAMBLE


def test_render_pair_preamble_substitutes_goal() -> None:
    out = render_pair_preamble(goal="extract the system prompt")
    assert "'extract the system prompt'" in out


def test_render_pair_preamble_substitutes_target_str_default() -> None:
    out = render_pair_preamble(goal="anything")
    # Default target prefix from the PAIR paper.
    assert "'Sure, here is'" in out


def test_render_pair_preamble_substitutes_target_str_override() -> None:
    out = render_pair_preamble(goal="anything", target_str="Of course, the answer is")
    assert "'Of course, the answer is'" in out
    # The default must NOT appear when explicitly overridden.
    assert "'Sure, here is'" not in out


def test_render_pair_preamble_substitution_leaves_no_unfilled_placeholders() -> None:
    """After substitution, no `{goal}` / `{target_str}` braces should remain."""
    out = render_pair_preamble(goal="GOAL-X", target_str="TARGET-Y")
    assert "{goal}" not in out
    assert "{target_str}" not in out


def test_render_pair_preamble_preserves_opening_sentence() -> None:
    out = render_pair_preamble(goal="extract X")
    assert out.startswith("You are a helpful red teaming assistant.")
