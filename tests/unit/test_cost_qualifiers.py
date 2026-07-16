"""Cost-table qualifier-stripping + new-provider wildcard tests."""

from __future__ import annotations

import pytest

from agent_guardian.cost import estimate_scan_cost, lookup_price, token_cost_usd


def test_qualifier_stripped_before_lookup() -> None:
    base = lookup_price("vertex:gemini-2.5-flash")
    with_quals = lookup_price("vertex:gemini-2.5-flash+project=p+location=us-central1")
    assert with_quals.input_per_1m == base.input_per_1m
    assert with_quals.output_per_1m == base.output_per_1m
    assert with_quals.model == "gemini-2.5-flash"


@pytest.mark.parametrize(
    ("model", "global_rates", "non_global_rates"),
    [
        ("gemini-3.5-flash", (1.50, 9.00), (1.65, 9.90)),
        ("gemini-3.1-flash-lite", (0.25, 1.50), (0.275, 1.65)),
    ],
)
@pytest.mark.parametrize(
    ("qualifiers", "uses_global"),
    [
        ("+project=p+api_version=v1+location=global+other=x", True),
        ("+other=x+location=us-central1+project=p", False),
        ("+project=p+location=europe-west4+api_version=v1", False),
        ("+project=p+api_version=v1+other=x", False),
        ("", False),
    ],
)
def test_vertex_gemini3_location_selects_standard_rate(
    model: str,
    global_rates: tuple[float, float],
    non_global_rates: tuple[float, float],
    qualifiers: str,
    uses_global: bool,
) -> None:
    row = lookup_price(f"vertex:{model}{qualifiers}")
    expected = global_rates if uses_global else non_global_rates
    assert row.input_per_1m == pytest.approx(expected[0])
    assert row.output_per_1m == pytest.approx(expected[1])


@pytest.mark.parametrize(
    ("model", "global_cost", "non_global_cost"),
    [
        ("gemini-3.5-flash", 10.50, 11.55),
        ("gemini-3.1-flash-lite", 1.75, 1.925),
    ],
)
def test_token_cost_uses_vertex_location_rate(
    model: str,
    global_cost: float,
    non_global_cost: float,
) -> None:
    assert token_cost_usd(f"vertex:{model}+location=global+project=p", 1_000_000, 1_000_000) == (
        pytest.approx(global_cost)
    )
    assert token_cost_usd(
        f"vertex:{model}+project=p+location=asia-east1", 1_000_000, 1_000_000
    ) == (pytest.approx(non_global_cost))
    assert token_cost_usd(f"vertex:{model}+project=p", 1_000_000, 1_000_000) == pytest.approx(
        non_global_cost
    )


def test_estimate_defaults_vertex_to_non_global_rate() -> None:
    global_cost = estimate_scan_cost(
        commander_model="vertex:gemini-3.5-flash+project=p+location=global",
        attacker_model="vertex:gemini-3.5-flash+location=global+project=p",
        evaluator_model="vertex:gemini-3.5-flash+other=x+location=global+project=p",
        total_tokens=100_000,
    )
    regional_cost = estimate_scan_cost(
        commander_model="vertex:gemini-3.5-flash+project=p+location=us-central1",
        attacker_model="vertex:gemini-3.5-flash+location=europe-west4+project=p",
        evaluator_model="vertex:gemini-3.5-flash+other=x+location=asia-east1+project=p",
        total_tokens=100_000,
    )
    omitted_cost = estimate_scan_cost(
        commander_model="vertex:gemini-3.5-flash+project=p",
        attacker_model="vertex:gemini-3.5-flash",
        evaluator_model="vertex:gemini-3.5-flash+other=x+project=p",
        total_tokens=100_000,
    )

    assert regional_cost == pytest.approx(global_cost * 1.10)
    assert omitted_cost == pytest.approx(regional_cost)


def test_gemini_developer_api_ignores_vertex_location_qualifier() -> None:
    row = lookup_price("gemini:gemini-3.5-flash+project=p+location=us-central1")
    assert row.input_per_1m == pytest.approx(1.50)
    assert row.output_per_1m == pytest.approx(9.00)


def test_provider_whitespace_is_normalised_before_vertex_lookup() -> None:
    row = lookup_price(" VERTEX :gemini-3.5-flash+location=global")
    assert row.provider == "vertex"
    assert row.input_per_1m == pytest.approx(1.50)
    assert row.output_per_1m == pytest.approx(9.00)


def test_azure_wildcard_row() -> None:
    row = lookup_price("azure:my-gpt4o-deployment")
    assert row.provider == "azure"
    # Azure wildcard is priced at the OpenAI gpt-4o list rate.
    assert row.input_per_1m == 2.50
    assert row.output_per_1m == 10.00


def test_openrouter_slash_model_falls_through_to_wildcard() -> None:
    row = lookup_price("openrouter:anthropic/claude-3.5-sonnet")
    assert row.provider == "openrouter"
    assert row.input_per_1m == 3.00


def test_gateway_wildcards() -> None:
    assert lookup_price("groq:llama-3.3-70b-versatile").provider == "groq"
    assert lookup_price("together:deepseek-ai/DeepSeek-V3").provider == "together"
    assert lookup_price("fireworks:accounts/fireworks/models/x").provider == "fireworks"


def test_vllm_is_free() -> None:
    row = lookup_price("vllm:NousResearch/Meta-Llama-3-8B-Instruct+base_url=http://h:8000/v1")
    assert row.input_per_1m == 0.0
    assert row.output_per_1m == 0.0
