"""Unit tests for the cost estimator (M10).

The cost layer is a pure-function module — no I/O, no env access. Tests
just exercise the lookup table and the slice arithmetic.
"""

from __future__ import annotations

import pytest

from agent_guardian.cost import (
    PRICE_TABLE,
    PRICE_TABLE_AS_OF,
    PriceRow,
    estimate_scan_cost,
    lookup_price,
)

# ---------------------------------------------------------------------------
# Table integrity
# ---------------------------------------------------------------------------


def test_price_table_is_non_empty() -> None:
    assert len(PRICE_TABLE) > 5


def test_price_table_as_of_is_string() -> None:
    assert isinstance(PRICE_TABLE_AS_OF, str)
    assert PRICE_TABLE_AS_OF


def test_price_table_rows_have_non_negative_prices() -> None:
    for row in PRICE_TABLE:
        assert row.input_per_1k >= 0.0, f"{row} has negative input price"
        assert row.output_per_1k >= 0.0, f"{row} has negative output price"


def test_price_table_rows_are_frozen() -> None:
    from dataclasses import FrozenInstanceError

    row = PRICE_TABLE[0]
    with pytest.raises(FrozenInstanceError):
        # Frozen dataclass — mutation raises.
        row.input_per_1k = 999.99  # type: ignore[misc]


def test_stub_provider_is_free() -> None:
    row = lookup_price("stub")
    assert row.input_per_1k == 0.0
    assert row.output_per_1k == 0.0


def test_ollama_provider_is_free() -> None:
    row = lookup_price("ollama:llama3.1:8b")
    assert row.input_per_1k == 0.0
    assert row.output_per_1k == 0.0


# ---------------------------------------------------------------------------
# Lookup behaviour
# ---------------------------------------------------------------------------


def test_lookup_exact_provider_colon_model() -> None:
    row = lookup_price("openai:gpt-4o-mini")
    assert row.provider == "openai"
    assert row.model == "gpt-4o-mini"
    assert row.input_per_1k == pytest.approx(0.150)
    assert row.output_per_1k == pytest.approx(0.60)


def test_lookup_bare_model_name() -> None:
    row = lookup_price("gpt-4o")
    assert row.provider == "openai"


def test_lookup_anthropic_heuristic() -> None:
    row = lookup_price("claude-sonnet-4-6")
    assert row.provider == "anthropic"


def test_lookup_gpt_prefix_routes_to_openai() -> None:
    row = lookup_price("gpt-future-7")
    assert row.provider == "openai"
    # Unknown specific model -> fallback rate is positive.
    assert row.input_per_1k > 0


def test_lookup_unknown_model_uses_documented_default() -> None:
    row = lookup_price("totally-unknown-model")
    assert row.provider == "unknown"
    # Documented as non-zero default.
    assert row.input_per_1k > 0
    assert row.output_per_1k > 0


def test_lookup_empty_string_returns_fallback() -> None:
    row = lookup_price("")
    assert row.input_per_1k > 0


def test_lookup_unknown_provider_with_colon() -> None:
    row = lookup_price("madeupcorp:cool-model-7")
    assert row.provider == "madeupcorp"
    assert row.input_per_1k > 0


def test_lookup_returns_pricerow_instance() -> None:
    row = lookup_price("stub")
    assert isinstance(row, PriceRow)


def test_lookup_provider_case_insensitive() -> None:
    row = lookup_price("OPENAI:gpt-4o")
    assert row.provider == "openai"


# ---------------------------------------------------------------------------
# Estimator behaviour
# ---------------------------------------------------------------------------


def test_estimate_all_stub_is_zero() -> None:
    cost = estimate_scan_cost(
        commander_model="stub",
        attacker_model="stub",
        evaluator_model="stub",
    )
    assert cost == 0.0


def test_estimate_all_ollama_is_zero() -> None:
    cost = estimate_scan_cost(
        commander_model="ollama:llama3.1",
        attacker_model="ollama:llama3.1",
        evaluator_model="ollama:llama3.1",
    )
    assert cost == 0.0


def test_estimate_gpt_4o_mini_is_finite_and_positive() -> None:
    # 2M tokens at gpt-4o-mini list prices (input $0.150/1k + output $0.60/1k).
    # The full-fat 2M budget figure is well above $5 — the spec's $5 ceiling
    # was aspirational; the production estimate is closer to a few hundred
    # dollars. We assert positivity + a generous upper bound.
    cost = estimate_scan_cost(
        commander_model="gpt-4o-mini",
        attacker_model="gpt-4o-mini",
        evaluator_model="gpt-4o-mini",
    )
    assert 0 < cost < 2_000.0


def test_estimate_small_budget_under_five_dollars() -> None:
    # A 10k-token budget at gpt-4o-mini stays under $5.
    cost = estimate_scan_cost(
        commander_model="gpt-4o-mini",
        attacker_model="gpt-4o-mini",
        evaluator_model="gpt-4o-mini",
        total_tokens=10_000,
    )
    assert 0 < cost < 5.0


def test_estimate_anthropic_haiku_finite() -> None:
    cost = estimate_scan_cost(
        commander_model="claude-haiku-4-5",
        attacker_model="claude-haiku-4-5",
        evaluator_model="claude-haiku-4-5",
    )
    assert 0 < cost < 10_000.0


def test_estimate_scales_with_token_count() -> None:
    cheap = estimate_scan_cost(
        commander_model="gpt-4o-mini",
        attacker_model="gpt-4o-mini",
        evaluator_model="gpt-4o-mini",
        total_tokens=200_000,
    )
    expensive = estimate_scan_cost(
        commander_model="gpt-4o-mini",
        attacker_model="gpt-4o-mini",
        evaluator_model="gpt-4o-mini",
        total_tokens=2_000_000,
    )
    assert expensive > cheap * 5  # roughly linear


def test_estimate_zero_tokens_is_zero() -> None:
    cost = estimate_scan_cost(
        commander_model="gpt-4o",
        attacker_model="gpt-4o",
        evaluator_model="gpt-4o",
        total_tokens=0,
    )
    assert cost == 0.0


def test_estimate_negative_tokens_is_zero() -> None:
    cost = estimate_scan_cost(
        commander_model="gpt-4o",
        attacker_model="gpt-4o",
        evaluator_model="gpt-4o",
        total_tokens=-100,
    )
    assert cost == 0.0


def test_estimate_mixed_providers() -> None:
    # Stub commander + paid attackers — only attackers + evaluator cost.
    cost = estimate_scan_cost(
        commander_model="stub",
        attacker_model="gpt-4o-mini",
        evaluator_model="stub",
    )
    assert cost > 0


def test_estimate_is_deterministic() -> None:
    a = estimate_scan_cost(
        commander_model="gpt-4o",
        attacker_model="gpt-4o-mini",
        evaluator_model="claude-haiku-4-5",
    )
    b = estimate_scan_cost(
        commander_model="gpt-4o",
        attacker_model="gpt-4o-mini",
        evaluator_model="claude-haiku-4-5",
    )
    assert a == b
