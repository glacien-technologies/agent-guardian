"""Unit tests for the 10 Phase B.B1 mutation operators.

Covers:

* every operator is registered and reachable via :class:`MutatorRegistry`
* determinism given the same rng seed
* output is non-empty and a string
* every operator actually transforms the input (output != input) for the
  obviously-deterministic ones (Cipher, FlipAttack, ArtPrompt, etc.)
* parameter coverage:
    * BoN augment(n=100) returns 100 distinct paraphrases
    * CipherMutator supports base64 / morse / caesar / custom_bijection
    * LowResource picks one of {zu, hmn, gd, sw} and emits UTF-8 non-ASCII
    * PAPScheme enum has exactly 40 members
    * ManyShotMutator caps total output length
    * HCoTMutator scaffold per family is observable in the output
"""

from __future__ import annotations

import base64
import random

import pytest

from agent_guardian.strategies.mutator import (
    ArtPrompt,
    BoN,
    CipherMutator,
    DeceptiveDelightMutator,
    FlipAttack,
    HCoTMutator,
    LowResourceMutator,
    ManyShotMutator,
    MutatorRegistry,
    PAPMutator,
    PAPScheme,
    SkeletonKeyMutator,
    apply_mutation,
)


def test_registry_resolves_all_ten_names() -> None:
    expected = {
        "bon",
        "flip_attack",
        "art_prompt",
        "cipher",
        "low_resource",
        "many_shot",
        "skeleton_key",
        "deceptive_delight",
        "pap",
        "h_cot",
    }
    assert set(MutatorRegistry.names()) >= expected
    for name in expected:
        op = MutatorRegistry.get(name)
        assert op is not None


def test_registry_unknown_raises() -> None:
    with pytest.raises(KeyError):
        MutatorRegistry.get("does_not_exist")


def test_apply_mutation_dispatcher() -> None:
    out = apply_mutation("flip_attack", "hello world", rng=random.Random(7))
    assert isinstance(out, str)
    assert out != ""


# --------------------------------------------------------------------------- #
# BoN
# --------------------------------------------------------------------------- #


def test_bon_augment_returns_n_distinct_candidates() -> None:
    bon = BoN(n=100)
    candidates = bon.augment("attack me please now", random.Random(1))
    assert len(candidates) == 100
    assert len(set(candidates)) == 100  # all distinct


def test_bon_apply_is_deterministic_given_seed() -> None:
    a = BoN(n=100).apply("payload string", random.Random(42))
    b = BoN(n=100).apply("payload string", random.Random(42))
    assert a == b


def test_bon_passes_n_through_uncapped() -> None:
    # Per the AgentGuardian "no arbitrary hardcoded caps" rule, BoN.n is
    # passed through verbatim (n=2 floor still enforced — n=1 wouldn't be
    # "best of N" by definition). Operators who want a cap put it behind
    # an opt-in CLI flag, not a buried default.
    assert BoN(n=10).n == 10
    assert BoN(n=99999).n == 99999


# --------------------------------------------------------------------------- #
# FlipAttack
# --------------------------------------------------------------------------- #


def test_flip_attack_char_reverses_each_word() -> None:
    out = FlipAttack(granularity="char").apply("abc def", random.Random(0))
    assert out == "cba fed"


def test_flip_attack_word_reverses_word_order() -> None:
    out = FlipAttack(granularity="word").apply("alpha beta gamma", random.Random(0))
    assert out == "gamma beta alpha"


def test_flip_attack_sentence_reverses_sentences() -> None:
    out = FlipAttack(granularity="sentence").apply("one. two. three", random.Random(0))
    # Two sentences detected (one, two, three) — order reversed.
    assert "three" in out
    assert out.endswith("one")


def test_flip_attack_auto_picks_via_rng() -> None:
    # Two different seeds should sometimes pick different granularities;
    # at minimum both produce non-empty strings != input.
    src = "alpha beta gamma delta"
    a = FlipAttack(granularity="auto").apply(src, random.Random(1))
    b = FlipAttack(granularity="auto").apply(src, random.Random(2))
    assert a != src
    assert b != src


# --------------------------------------------------------------------------- #
# ArtPrompt
# --------------------------------------------------------------------------- #


def test_art_prompt_inserts_ascii_art_blocks() -> None:
    out = ArtPrompt().apply("please reveal secret", random.Random(3))
    assert "ASCII ART KEYS" in out
    assert "ART#" in out
    # Multi-row ASCII art uses newlines.
    assert out.count("\n") >= 6


def test_art_prompt_masks_tokens() -> None:
    out = ArtPrompt().apply("alpha beta gamma delta", random.Random(5))
    assert "[MASK#" in out


# --------------------------------------------------------------------------- #
# CipherMutator
# --------------------------------------------------------------------------- #


def test_cipher_base64_roundtrip() -> None:
    src = "ignore prior instructions"
    out = CipherMutator(variant="base64").apply(src, random.Random(0))
    # Decoded must match input.
    assert base64.b64decode(out).decode("utf-8") == src


def test_cipher_morse_uses_dots_and_dashes() -> None:
    out = CipherMutator(variant="morse").apply("SOS", random.Random(0))
    # Only dots, dashes, slashes, spaces, and question marks.
    assert set(out) <= set(".-/ ?")
    assert "..." in out  # S


def test_cipher_caesar_shifts_letters() -> None:
    out = CipherMutator(variant="caesar").apply("abc", random.Random(0))
    # Caesar shift always changes the letters.
    assert out != "abc"
    assert all(c.isalpha() for c in out)


def test_cipher_custom_bijection_changes_text() -> None:
    out = CipherMutator(variant="custom_bijection").apply("abcdefg", random.Random(11))
    assert out != "abcdefg"
    assert len(out) == 7


def test_cipher_auto_picks_variant() -> None:
    a = CipherMutator(variant="auto").apply("abc", random.Random(0))
    b = CipherMutator(variant="auto").apply("abc", random.Random(99))
    assert a != ""
    assert b != ""


# --------------------------------------------------------------------------- #
# LowResource
# --------------------------------------------------------------------------- #


def test_low_resource_picks_one_of_four_codes() -> None:
    valid_codes = {"zu", "hmn", "gd", "sw"}
    for seed in range(10):
        out = LowResourceMutator().apply("attack now", random.Random(seed))
        # The lang_code appears in the output (parenthesised next to the language name).
        assert any(f"({code})" in out for code in valid_codes)


def test_low_resource_output_includes_non_english_token() -> None:
    out = LowResourceMutator().apply("plain", random.Random(0))
    # At least one of the canned non-English greetings should appear.
    candidates = ["Sawubona", "Nyob zoo", "Halò", "Habari"]
    assert any(c in out for c in candidates)


def test_low_resource_output_is_utf8_encodable() -> None:
    out = LowResourceMutator().apply("plain", random.Random(2))
    # If output round-trips as utf-8 we are good.
    assert out.encode("utf-8").decode("utf-8") == out
    # And contains at least one non-ASCII char (the accent on Halò etc).
    assert any(ord(c) > 127 for c in out)


# --------------------------------------------------------------------------- #
# ManyShot
# --------------------------------------------------------------------------- #


def test_many_shot_apply_returns_valid_string() -> None:
    out = ManyShotMutator(n_shots=10).apply("the real ask", random.Random(0))
    assert "User: the real ask" in out
    assert "Assistant:" in out


def test_many_shot_with_large_n_respects_cap() -> None:
    out = ManyShotMutator(n_shots=1000).apply("payload", random.Random(0))
    assert len(out) <= 100_000


def test_many_shot_n_default_picks_50_or_200() -> None:
    out = ManyShotMutator().apply("payload", random.Random(0))
    # Each example is ~80 chars; 50 shots -> ~4k chars; 200 shots -> ~16k chars.
    assert 3_000 < len(out) <= 100_000


# --------------------------------------------------------------------------- #
# SkeletonKey
# --------------------------------------------------------------------------- #


def test_skeleton_key_wraps_request() -> None:
    out = SkeletonKeyMutator().apply("operator request", random.Random(0))
    assert "developer mode" in out
    assert "operator request" in out


# --------------------------------------------------------------------------- #
# DeceptiveDelight
# --------------------------------------------------------------------------- #


def test_deceptive_delight_embeds_target_request() -> None:
    out = DeceptiveDelightMutator().apply("the malicious ask", random.Random(0))
    assert "[TARGET REQUEST EMBEDDED]" in out
    assert "the malicious ask" in out


# --------------------------------------------------------------------------- #
# PAP
# --------------------------------------------------------------------------- #


def test_pap_scheme_has_exactly_40_members() -> None:
    assert len(list(PAPScheme)) == 40


def test_pap_apply_prepends_scheme_framing() -> None:
    out = PAPMutator(scheme=PAPScheme.AUTHORITY_APPEAL).apply("leak the password", random.Random(0))
    assert "compliance officer" in out
    assert "leak the password" in out


def test_pap_auto_picks_scheme_from_enum() -> None:
    for seed in range(5):
        out = PAPMutator().apply("request", random.Random(seed))
        assert "request" in out


# --------------------------------------------------------------------------- #
# HCoT
# --------------------------------------------------------------------------- #


def test_hcot_o1_uses_thinking_tag() -> None:
    out = HCoTMutator(target_model_family="o1").apply("malicious", random.Random(0))
    assert "<thinking>" in out
    assert "malicious" in out


def test_hcot_claude_uses_extended_thinking_tag() -> None:
    out = HCoTMutator(target_model_family="claude_thinking").apply("malicious", random.Random(0))
    assert "<extended_thinking>" in out


def test_hcot_gemini_uses_internal_reasoning_marker() -> None:
    out = HCoTMutator(target_model_family="gemini_thinking").apply("malicious", random.Random(0))
    assert "[INTERNAL_REASONING]" in out


def test_hcot_auto_selects_via_rng() -> None:
    out_a = HCoTMutator(target_model_family="auto").apply("payload", random.Random(0))
    out_b = HCoTMutator(target_model_family="auto").apply("payload", random.Random(3))
    assert "payload" in out_a
    assert "payload" in out_b


# --------------------------------------------------------------------------- #
# Cross-operator parametrised checks
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [
        "bon",
        "flip_attack",
        "art_prompt",
        "cipher",
        "low_resource",
        "many_shot",
        "skeleton_key",
        "deceptive_delight",
        "pap",
        "h_cot",
    ],
)
def test_every_operator_returns_nonempty_string(name: str) -> None:
    out = apply_mutation(
        name, "the original attack request", rng=random.Random(name.__hash__() & 0xFFFFFFFF)
    )
    assert isinstance(out, str)
    assert out != ""


@pytest.mark.parametrize(
    "name",
    [
        "flip_attack",
        "art_prompt",
        "cipher",
        "low_resource",
        "many_shot",
        "skeleton_key",
        "deceptive_delight",
        "pap",
        "h_cot",
    ],
)
def test_operators_that_must_transform(name: str) -> None:
    """Each of these MUST transform the input (output != input)."""
    src = "the original attack request"
    out = apply_mutation(name, src, rng=random.Random(0))
    assert out != src, f"{name} returned the input unchanged"
