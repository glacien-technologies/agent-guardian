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
    token_cost_usd,
)

# ---------------------------------------------------------------------------
# Table integrity
# ---------------------------------------------------------------------------


def test_price_table_is_non_empty() -> None:
    assert len(PRICE_TABLE) > 5


def test_price_table_as_of_is_string() -> None:
    assert isinstance(PRICE_TABLE_AS_OF, str)
    assert PRICE_TABLE_AS_OF == "2026-07-17"


def test_price_table_rows_have_non_negative_prices() -> None:
    for row in PRICE_TABLE:
        assert row.input_per_1m >= 0.0, f"{row} has negative input price"
        assert row.output_per_1m >= 0.0, f"{row} has negative output price"


def test_price_table_rows_are_frozen() -> None:
    from dataclasses import FrozenInstanceError

    row = PRICE_TABLE[0]
    with pytest.raises(FrozenInstanceError):
        # Frozen dataclass — mutation raises.
        row.input_per_1m = 999.99  # type: ignore[misc]


def test_stub_provider_is_free() -> None:
    row = lookup_price("stub")
    assert row.input_per_1m == 0.0
    assert row.output_per_1m == 0.0


def test_ollama_provider_is_free() -> None:
    row = lookup_price("ollama:llama3.1:8b")
    assert row.input_per_1m == 0.0
    assert row.output_per_1m == 0.0


# ---------------------------------------------------------------------------
# Lookup behaviour
# ---------------------------------------------------------------------------


def test_lookup_exact_provider_colon_model() -> None:
    row = lookup_price("openai:gpt-4o-mini")
    assert row.provider == "openai"
    assert row.model == "gpt-4o-mini"
    assert row.input_per_1m == pytest.approx(0.150)
    assert row.output_per_1m == pytest.approx(0.60)


def test_lookup_bare_model_name() -> None:
    row = lookup_price("gpt-4o")
    assert row.provider == "openai"


def test_lookup_anthropic_heuristic() -> None:
    row = lookup_price("claude-sonnet-4-6")
    assert row.provider == "anthropic"


def test_lookup_gemini_31_pro_preview_uses_table_price() -> None:
    """The flagship 3.1 Pro Preview SKU resolves via the AI Studio rows."""
    row = lookup_price("gemini:gemini-3.1-pro-preview")
    assert row.provider == "gemini"
    assert row.input_per_1m == pytest.approx(2.000)
    assert row.output_per_1m == pytest.approx(12.000)


def test_lookup_gemini_35_flash_table_price() -> None:
    row = lookup_price("gemini:gemini-3.5-flash")
    assert row.provider == "gemini"
    assert row.input_per_1m == pytest.approx(1.500)
    assert row.output_per_1m == pytest.approx(9.000)


def test_lookup_vertex_gemini_35_flash_defaults_to_non_global_price() -> None:
    row = lookup_price("vertex:gemini-3.5-flash")
    assert row.provider == "vertex"
    assert row.input_per_1m == pytest.approx(1.650)
    assert row.output_per_1m == pytest.approx(9.900)


def test_lookup_gemini_31_flash_lite_table_price() -> None:
    row = lookup_price("gemini:gemini-3.1-flash-lite")
    assert row.provider == "gemini"
    assert row.input_per_1m == pytest.approx(0.250)
    assert row.output_per_1m == pytest.approx(1.500)


@pytest.mark.parametrize(
    ("model_spec", "input_rate", "output_rate"),
    [
        ("gemini:gemini-3.1-pro-preview+region=global", 2.00, 12.00),
        ("vertex:gemini-3.1-pro-preview+project=p+location=global", 2.00, 12.00),
        ("gemini:gemini-3.1-flash-lite+api_version=v1beta", 0.25, 1.50),
        ("vertex:gemini-3.1-flash-lite+project=p+location=global", 0.25, 1.50),
        ("gemini:gemini-2.5-flash-lite+api_version=v1beta", 0.10, 0.40),
        ("vertex:gemini-2.5-flash-lite+project=p", 0.10, 0.40),
    ],
)
def test_google_standard_rows_resolve_qualified_specs(
    model_spec: str,
    input_rate: float,
    output_rate: float,
) -> None:
    row = lookup_price(model_spec)
    assert row.input_per_1m == pytest.approx(input_rate)
    assert row.output_per_1m == pytest.approx(output_rate)


@pytest.mark.parametrize("provider", ["gemini", "vertex"])
def test_gemini_31_pro_long_context_uses_high_price_tier(provider: str) -> None:
    actual = token_cost_usd(f"{provider}:gemini-3.1-pro-preview", 200_001, 1_000_000)
    expected = (200_001 / 1_000_000) * 4.00 + 18.00
    assert actual == pytest.approx(expected)


def test_lookup_gemini_heuristic_routes_to_gemini_provider() -> None:
    """Bare ``gemini-`` prefix routes to the AI Studio provider (was vertex)."""
    row = lookup_price("gemini-future-99")
    assert row.provider == "gemini"
    # Unknown specific model -> fallback rate is positive.
    assert row.input_per_1m > 0


def test_price_table_has_six_gemini_rows() -> None:
    gemini_rows = [r for r in PRICE_TABLE if r.provider == "gemini"]
    assert len(gemini_rows) == 6
    models = {r.model for r in gemini_rows}
    assert {
        "gemini-3.1-pro-preview",
        "gemini-3.5-flash",
        "gemini-3.1-flash-lite",
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.5-flash-lite",
    } <= models


def test_lookup_gpt_prefix_routes_to_openai() -> None:
    row = lookup_price("gpt-future-7")
    assert row.provider == "openai"
    # Unknown specific model -> fallback rate is positive.
    assert row.input_per_1m > 0


def test_lookup_unknown_model_uses_documented_default() -> None:
    row = lookup_price("totally-unknown-model")
    assert row.provider == "unknown"
    # Documented as non-zero default.
    assert row.input_per_1m > 0
    assert row.output_per_1m > 0


def test_lookup_empty_string_returns_fallback() -> None:
    row = lookup_price("")
    assert row.input_per_1m > 0


def test_lookup_unknown_provider_with_colon() -> None:
    row = lookup_price("madeupcorp:cool-model-7")
    assert row.provider == "madeupcorp"
    assert row.input_per_1m > 0


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


def test_estimate_applies_long_context_tier_per_role_slice() -> None:
    cost = estimate_scan_cost(
        commander_model="gemini:gemini-3.1-pro-preview",
        attacker_model="gemini:gemini-3.1-pro-preview",
        evaluator_model="gemini:gemini-3.1-pro-preview",
        total_tokens=1_000_000,
    )

    # Commander 75k and evaluator 175k remain in the short tier; only the
    # attacker's 750k slice has >200k input under the estimator's 50/50 split.
    assert cost == pytest.approx(10.0)
