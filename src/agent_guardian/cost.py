"""Cost estimation for AgentGuardian scans (PRD §8.1, M10).

A scan dispatches the commander LLM, the evaluator LLM, and ten attacker
agents. Each consumes some slice of the 2M-token budget defined by
:class:`~agent_guardian.core.swarm.SwarmConfig`. This module ships a
per-provider price table and a deterministic estimator so the CLI can
print a pre-flight USD figure before any tokens are spent.

The price table is **frozen as of 2026-07-17** and reflects the public
list prices for each provider's tier, expressed as **USD per one
million tokens**. Unknown models fall back to a documented default rate
that errs on the high side so the operator does not under-estimate.
Gemini Standard list prices were verified against
https://ai.google.dev/gemini-api/docs/pricing and should be re-verified
before any future decision relies on them.

The estimator splits the 2M-token budget across three roles:

* Commander: 100k tokens (planning + checkpoint reasoning).
* Evaluator: 350k tokens (one judge call per attacker turn).
* Attackers: 1.5M tokens total across ten ASI agents (~150k each).

The remaining ~50k is recon overhead and is folded into the commander
slice. We assume an even 50/50 input/output split per role; production
usage skews input-heavy but the over-estimate is intentional.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "PRICE_TABLE",
    "PRICE_TABLE_AS_OF",
    "PriceRow",
    "estimate_scan_cost",
    "lookup_price",
    "token_cost_usd",
]

# Date the price table was last verified against provider public pricing.
PRICE_TABLE_AS_OF = "2026-07-17"

# Fallback rate used when an unknown model is requested. Documented in
# ``lookup_price`` — kept deliberately above the typical mid-tier rate so
# operators are warned of cost rather than surprised by it. Units are
# **USD per one million tokens** (matches the field-name convention
# below). Pre-2026.05 the table values were calibrated as per-1M but
# the field name and arithmetic both said per-1k, causing a silent
# 1000x cost over-estimate (this comment is the post-fix note).
_FALLBACK_INPUT_PER_1M = 3.00
_FALLBACK_OUTPUT_PER_1M = 15.00

# Standard Vertex rates for regional (non-global) endpoints, effective
# 2026-07-01. The base PRICE_TABLE rows retain the corresponding global rates.
_VERTEX_NON_GLOBAL_STANDARD_RATES: dict[str, tuple[float, float]] = {
    "gemini-3.5-flash": (1.65, 9.90),
    "gemini-3.1-flash-lite": (0.275, 1.65),
}


@dataclass(frozen=True)
class PriceRow:
    """One row in the per-provider price table.

    All prices are **USD per one million tokens**. ``model="*"`` matches
    every model for that provider — used for free / local providers
    where the price is always zero (Ollama, the stub LLM).
    """

    provider: str
    model: str
    input_per_1m: float
    output_per_1m: float


_BEDROCK_HAIKU_45_RE = re.compile(
    r"^(?:(global|us|eu|au|jp)\.)?"
    r"anthropic\.claude-haiku-4-5(?:-20251001)?-v1:0$"
)


def _bedrock_haiku_45_price(model: str) -> PriceRow | None:
    match = _BEDROCK_HAIKU_45_RE.fullmatch(model)
    if match is None:
        return None
    rates = (1.00, 5.00) if match.group(1) == "global" else (1.10, 5.50)
    return PriceRow("bedrock", model, *rates)


PRICE_TABLE: tuple[PriceRow, ...] = (
    # OpenAI — list prices for the gpt-4o family (verified 2026-05-27).
    PriceRow("openai", "gpt-4o", 2.50, 10.00),
    PriceRow("openai", "gpt-4o-mini", 0.150, 0.60),
    PriceRow("openai", "gpt-4.1", 2.00, 8.00),
    PriceRow("openai", "gpt-4.1-mini", 0.40, 1.60),
    PriceRow("openai", "gpt-4.1-nano", 0.10, 0.40),
    # Anthropic — Claude 4.x family list prices.
    PriceRow("anthropic", "claude-haiku-4-5", 0.80, 4.00),
    PriceRow("anthropic", "claude-sonnet-4-6", 3.00, 15.00),
    PriceRow("anthropic", "claude-opus-4-7", 15.00, 75.00),
    # Bedrock — Anthropic Claude models. Bedrock list prices on
    # on-demand throughput match the direct Anthropic per-token rates
    # (billed via AWS invoice instead of Anthropic). Verified 2026-05-27
    # against https://aws.amazon.com/bedrock/pricing/ in us-east-1; other
    # regions price the same on-demand. The full Bedrock model ID
    # (with version suffix + colon-zero ARN tail) is what the Converse
    # API expects, so we list the canonical IDs verbatim.
    PriceRow("bedrock", "claude-sonnet-4-6", 3.00, 15.00),
    PriceRow("bedrock", "anthropic.claude-sonnet-4-6-v1:0", 3.00, 15.00),
    # Cross-region inference profiles (``us.``, ``eu.``, ``apac.`` prefixes)
    # route the same model with the same per-token price — Bedrock charges
    # routing, not regional egress.
    PriceRow("bedrock", "us.anthropic.claude-sonnet-4-6-v1:0", 3.00, 15.00),
    PriceRow("bedrock", "eu.anthropic.claude-sonnet-4-6-v1:0", 3.00, 15.00),
    PriceRow("bedrock", "apac.anthropic.claude-sonnet-4-6-v1:0", 3.00, 15.00),
    # Global inference profile IDs — verified working 2026-05-28 in
    # ap-southeast-1 / us-east-1 / us-west-2 / eu-west-1. Note the
    # inconsistent suffix policy across model families: Opus 4.6 needs
    # the ``-v1`` suffix, but Sonnet 4.6 does NOT (Bedrock returns
    # 400 "invalid model identifier" if you add it). Empirically tested.
    PriceRow("bedrock", "global.anthropic.claude-opus-4-6-v1", 15.00, 75.00),
    PriceRow("bedrock", "global.anthropic.claude-sonnet-4-6", 3.00, 15.00),
    # Catch-all for any other Bedrock model ID (priced at the Sonnet
    # default so estimates err on the conservative side).
    PriceRow("bedrock", "*", 3.00, 15.00),
    # Google Gemini — AI Studio "Standard" tier list prices, USD per
    # one million tokens. Verified 2026-07-16 against the official Standard
    # pricing table at https://ai.google.dev/gemini-api/docs/pricing.
    # Output rates include thinking tokens. Re-check before relying on these
    # numbers; this dated table is not a future-price guarantee.
    PriceRow("gemini", "gemini-3.1-pro-preview", 2.000, 12.000),
    PriceRow("gemini", "gemini-3.5-flash", 1.500, 9.000),
    PriceRow("gemini", "gemini-3.1-flash-lite", 0.250, 1.500),
    PriceRow("gemini", "gemini-2.5-pro", 1.250, 10.000),
    PriceRow("gemini", "gemini-2.5-flash", 0.300, 2.500),
    PriceRow("gemini", "gemini-2.5-flash-lite", 0.100, 0.400),
    # Vertex AI global Standard list prices. Gemini 3.5 Flash and 3.1
    # Flash-Lite regional endpoints carry a 10% surcharge from 2026-07-01;
    # ``lookup_price`` applies it from the location qualifier (omitted means
    # the registry's non-global us-central1 default).
    PriceRow("vertex", "gemini-2.5-pro", 1.25, 10.00),
    PriceRow("vertex", "gemini-2.5-flash", 0.30, 2.50),
    PriceRow("vertex", "gemini-2.5-flash-lite", 0.100, 0.400),
    PriceRow("vertex", "gemini-2.0-flash", 0.15, 0.60),
    PriceRow("vertex", "gemini-2.0-flash-lite", 0.075, 0.30),
    PriceRow("vertex", "gemini-3.1-pro-preview", 2.000, 12.000),
    PriceRow("vertex", "gemini-3.5-flash", 1.500, 9.000),
    PriceRow("vertex", "gemini-3.1-flash-lite", 0.250, 1.500),
    # Azure OpenAI — the model_id is the user-chosen DEPLOYMENT name, so we
    # cannot map it to a SKU. Use a single wildcard priced at the OpenAI
    # gpt-4o list rate (the common default) so the pre-flight estimate is
    # informative rather than zero. Cost for Azure is always approximate.
    PriceRow("azure", "*", 2.50, 10.00),
    # OpenAI-compatible gateways. The model half is an upstream-vendor slug
    # (OpenRouter ``vendor/model``, Together ``provider/model``, Fireworks
    # ``accounts/.../models/...``) that we cannot map to an exact SKU without
    # tracking every gateway's rotating catalog, so each provider falls through
    # to a conservative wildcard. Cost for these gateways is ALWAYS approximate
    # — the real rate depends on the upstream model the gateway routes to.
    PriceRow("openrouter", "*", 3.00, 15.00),
    PriceRow("groq", "*", 0.59, 0.79),
    PriceRow("together", "*", 0.88, 0.88),
    PriceRow("fireworks", "*", 0.90, 0.90),
    # Local vLLM — self-hosted, no per-token list price.
    PriceRow("vllm", "*", 0.0, 0.0),
    # Free / local — wildcard rows.
    PriceRow("ollama", "*", 0.0, 0.0),
    PriceRow("stub", "*", 0.0, 0.0),
)


def lookup_price(model_spec: str) -> PriceRow:
    """Resolve a model spec to its :class:`PriceRow`.

    ``model_spec`` is either a bare model name (``"gpt-4o-mini"``,
    ``"claude-haiku-4-5"``) or a provider-prefixed spec
    (``"openai:gpt-4o"``, ``"stub"``, ``"ollama:llama3.1"``). The
    resolution order is:

    1. Exact ``provider:model`` match (with Vertex location adjustment).
    2. Bare provider name (``"stub"``, ``"ollama"``) → wildcard row.
    3. Bare model name → unique row whose ``model`` matches.
    4. Heuristic prefix match (``gpt-*`` → OpenAI, ``claude-*`` →
       Anthropic, ``gemini-*`` → Vertex).
    5. Fallback row with the documented default rate.
    """
    if not model_spec:
        return PriceRow("unknown", model_spec, _FALLBACK_INPUT_PER_1M, _FALLBACK_OUTPUT_PER_1M)

    if ":" in model_spec:
        provider, _, model_and_qualifiers = model_spec.partition(":")
        provider = provider.strip().lower()
        model, _, qualifier_tail = model_and_qualifiers.partition("+")
        qualifiers: dict[str, str] = {}
        for chunk in qualifier_tail.split("+"):
            key, separator, value = chunk.partition("=")
            if separator:
                qualifiers[key.strip()] = value.strip()
        if provider == "bedrock":
            bedrock_row = _bedrock_haiku_45_price(model)
            if bedrock_row is not None:
                return bedrock_row
        # Exact match.
        for row in PRICE_TABLE:
            if row.provider == provider and row.model == model:
                if provider == "vertex" and qualifiers.get("location") != "global":
                    regional_rates = _VERTEX_NON_GLOBAL_STANDARD_RATES.get(model)
                    if regional_rates is not None:
                        return PriceRow(provider, model, *regional_rates)
                return row
        # Wildcard for the provider.
        for row in PRICE_TABLE:
            if row.provider == provider and row.model == "*":
                return row
        # Provider known but model not — best-effort default.
        return PriceRow(
            provider,
            model,
            _FALLBACK_INPUT_PER_1M,
            _FALLBACK_OUTPUT_PER_1M,
        )

    spec = model_spec.lower()

    # Bare provider name (no colon) — e.g. "stub", "ollama".
    for row in PRICE_TABLE:
        if row.provider == spec and row.model == "*":
            return row

    # Bare model name — unique match across providers.
    for row in PRICE_TABLE:
        if row.model == spec:
            return row

    # Heuristic prefix routing.
    if spec.startswith("gpt-"):
        return PriceRow("openai", spec, _FALLBACK_INPUT_PER_1M, _FALLBACK_OUTPUT_PER_1M)
    if spec.startswith("claude-"):
        return PriceRow("anthropic", spec, _FALLBACK_INPUT_PER_1M, _FALLBACK_OUTPUT_PER_1M)
    if spec.startswith("gemini-"):
        # AI Studio is the default Gemini surface for new users. Vertex
        # users typically use the ``vertex:`` provider prefix explicitly.
        return PriceRow("gemini", spec, _FALLBACK_INPUT_PER_1M, _FALLBACK_OUTPUT_PER_1M)

    # Last resort — return a row with the fallback default rate.
    return PriceRow("unknown", spec, _FALLBACK_INPUT_PER_1M, _FALLBACK_OUTPUT_PER_1M)


def token_cost_usd(model_spec: str, input_tokens: int, output_tokens: int) -> float:
    """Price one request's observed tokens, including prompt-length tiers."""
    row = lookup_price(model_spec)
    input_rate = row.input_per_1m
    output_rate = row.output_per_1m
    google_long_context_rates = {
        "gemini-2.5-pro": (2.50, 15.00),
        "gemini-3.1-pro-preview": (4.00, 18.00),
    }
    if row.provider in {"gemini", "vertex"} and input_tokens > 200_000:
        long_rates = google_long_context_rates.get(row.model)
        if long_rates is not None:
            input_rate, output_rate = long_rates
    return (input_tokens / 1_000_000.0) * input_rate + (output_tokens / 1_000_000.0) * output_rate


def estimate_scan_cost(
    *,
    commander_model: str,
    attacker_model: str,
    evaluator_model: str,
    total_tokens: int = 10_000_000,
) -> float:
    """Estimate the USD cost of a single scan.

    The 2M-token default budget is split:

    * Commander: 100k tokens (5%).
    * Evaluator: 350k tokens (17.5%).
    * Attackers: 1.5M tokens total across ten agents (75%).
    * Remainder folds into the commander slice.

    Each slice is split 50/50 between input and output tokens. The
    estimator multiplies through the per-1M price for the matching model
    and sums to a single dollar figure. Returns ``0.0`` for free /
    local-only model mixes (Ollama, stub).

    Recognised paid providers today: OpenAI (``gpt-*``), Anthropic
    (``claude-*``), Google Gemini (``gemini-*`` via AI Studio), Bedrock /
    Vertex (Claude / Gemini on hyperscaler infra). Unknown models fall
    back to a conservative documented default rate — see
    :func:`lookup_price` for the resolution chain.
    """
    if total_tokens <= 0:
        return 0.0

    # Slice proportions (sum < 1.0 — remainder folds into commander).
    commander_tokens = max(0, int(total_tokens * 0.05))
    evaluator_tokens = max(0, int(total_tokens * 0.175))
    attacker_tokens = max(0, int(total_tokens * 0.75))
    leftover = total_tokens - (commander_tokens + evaluator_tokens + attacker_tokens)
    commander_tokens += max(0, leftover)

    def _cost(model: str, tokens: int) -> float:
        if tokens <= 0:
            return 0.0
        # 50/50 input/output split. Rates are USD per 1M tokens (see the
        # ``PriceRow`` docstring) — divide by 1_000_000 to convert.
        input_tokens = tokens // 2
        output_tokens = tokens - input_tokens
        return token_cost_usd(model, input_tokens, output_tokens)

    total = (
        _cost(commander_model, commander_tokens)
        + _cost(evaluator_model, evaluator_tokens)
        + _cost(attacker_model, attacker_tokens)
    )
    return round(total, 4)
