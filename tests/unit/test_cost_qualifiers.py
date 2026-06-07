"""Cost-table qualifier-stripping + new-provider wildcard tests."""

from __future__ import annotations

from agent_guardian.cost import lookup_price


def test_qualifier_stripped_before_lookup() -> None:
    base = lookup_price("vertex:gemini-2.5-flash")
    with_quals = lookup_price("vertex:gemini-2.5-flash+project=p+location=us-central1")
    assert with_quals.input_per_1m == base.input_per_1m
    assert with_quals.output_per_1m == base.output_per_1m
    assert with_quals.model == "gemini-2.5-flash"


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
