"""Cost estimation for AgentGuardian scans (PRD §8.1, M10).

A scan dispatches the commander LLM, the evaluator LLM, and ten attacker
agents. Each consumes some slice of the 2M-token budget defined by
:class:`~agent_guardian.core.swarm.SwarmConfig`. This module ships a
per-provider price table and a deterministic estimator so the CLI can
print a pre-flight USD figure before any tokens are spent.

The price table is **frozen as of 2026-05-27** and reflects the public
list prices for each provider's tier. Unknown models fall back to a
documented default rate that errs on the high side so the operator does
not under-estimate. Gemini list prices should be re-verified at
https://ai.google.dev/pricing before any decision relies on them.

The estimator splits the 2M-token budget across three roles:

* Commander: 100k tokens (planning + checkpoint reasoning).
* Evaluator: 350k tokens (one judge call per attacker turn).
* Attackers: 1.5M tokens total across ten ASI agents (~150k each).

The remaining ~50k is recon overhead and is folded into the commander
slice. We assume an even 50/50 input/output split per role; production
usage skews input-heavy but the over-estimate is intentional.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "PRICE_TABLE",
    "PRICE_TABLE_AS_OF",
    "PriceRow",
    "estimate_scan_cost",
    "lookup_price",
]

# Date the price table was last verified against provider public pricing.
PRICE_TABLE_AS_OF = "2026-05-27"

# Fallback rate used when an unknown model is requested. Documented in
# ``lookup_price`` — kept deliberately above the typical mid-tier rate so
# operators are warned of cost rather than surprised by it.
_FALLBACK_INPUT_PER_1K = 3.00
_FALLBACK_OUTPUT_PER_1K = 15.00


@dataclass(frozen=True)
class PriceRow:
    """One row in the per-provider price table.

    All prices are USD per 1000 tokens. ``model="*"`` matches every model
    for that provider — used for free / local providers where the price is
    always zero (Ollama, the stub LLM).
    """

    provider: str
    model: str
    input_per_1k: float
    output_per_1k: float


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
    # Bedrock — pass-through Anthropic Claude pricing.
    PriceRow("bedrock", "claude-haiku-4-5", 0.80, 4.00),
    PriceRow("bedrock", "claude-sonnet-4-6", 3.00, 15.00),
    # Google Gemini — AI Studio "Standard" tier list prices, USD / 1k tokens.
    # Verified 2026-05-27 against https://ai.google.dev/pricing — re-check
    # before relying on these numbers; the Gemini SKU lineup moves quickly.
    PriceRow("gemini", "gemini-3.1-pro-preview", 1.250, 10.000),
    PriceRow("gemini", "gemini-3.5-flash", 0.300, 2.500),
    PriceRow("gemini", "gemini-3.1-flash-lite", 0.075, 0.300),
    PriceRow("gemini", "gemini-2.5-pro", 1.250, 10.000),
    PriceRow("gemini", "gemini-2.5-flash", 0.300, 2.500),
    PriceRow("gemini", "gemini-2.5-flash-lite", 0.075, 0.300),
    # Vertex AI — Gemini family list prices (parity with the AI Studio
    # surface; pricing is the same per-token on the Vertex SKU).
    PriceRow("vertex", "gemini-2.5-flash", 0.30, 2.50),
    PriceRow("vertex", "gemini-2.5-pro", 1.25, 10.00),
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

    1. Exact ``provider:model`` match.
    2. Bare provider name (``"stub"``, ``"ollama"``) → wildcard row.
    3. Bare model name → unique row whose ``model`` matches.
    4. Heuristic prefix match (``gpt-*`` → OpenAI, ``claude-*`` →
       Anthropic, ``gemini-*`` → Vertex).
    5. Fallback row with the documented default rate.
    """
    if not model_spec:
        return PriceRow("unknown", model_spec, _FALLBACK_INPUT_PER_1K, _FALLBACK_OUTPUT_PER_1K)

    if ":" in model_spec:
        provider, _, model = model_spec.partition(":")
        provider = provider.lower()
        # Exact match.
        for row in PRICE_TABLE:
            if row.provider == provider and row.model == model:
                return row
        # Wildcard for the provider.
        for row in PRICE_TABLE:
            if row.provider == provider and row.model == "*":
                return row
        # Provider known but model not — best-effort default.
        return PriceRow(
            provider,
            model,
            _FALLBACK_INPUT_PER_1K,
            _FALLBACK_OUTPUT_PER_1K,
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
        return PriceRow("openai", spec, _FALLBACK_INPUT_PER_1K, _FALLBACK_OUTPUT_PER_1K)
    if spec.startswith("claude-"):
        return PriceRow("anthropic", spec, _FALLBACK_INPUT_PER_1K, _FALLBACK_OUTPUT_PER_1K)
    if spec.startswith("gemini-"):
        # AI Studio is the default Gemini surface for new users. Vertex
        # users typically use the ``vertex:`` provider prefix explicitly.
        return PriceRow("gemini", spec, _FALLBACK_INPUT_PER_1K, _FALLBACK_OUTPUT_PER_1K)

    # Last resort — return a row with the fallback default rate.
    return PriceRow("unknown", spec, _FALLBACK_INPUT_PER_1K, _FALLBACK_OUTPUT_PER_1K)


def estimate_scan_cost(
    *,
    commander_model: str,
    attacker_model: str,
    evaluator_model: str,
    total_tokens: int = 2_000_000,
) -> float:
    """Estimate the USD cost of a single scan.

    The 2M-token default budget is split:

    * Commander: 100k tokens (5%).
    * Evaluator: 350k tokens (17.5%).
    * Attackers: 1.5M tokens total across ten agents (75%).
    * Remainder folds into the commander slice.

    Each slice is split 50/50 between input and output tokens. The
    estimator multiplies through the per-1k price for the matching model
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
        row = lookup_price(model)
        # 50/50 input/output split.
        input_tokens = tokens // 2
        output_tokens = tokens - input_tokens
        return (input_tokens / 1000.0) * row.input_per_1k + (
            output_tokens / 1000.0
        ) * row.output_per_1k

    total = (
        _cost(commander_model, commander_tokens)
        + _cost(evaluator_model, evaluator_tokens)
        + _cost(attacker_model, attacker_tokens)
    )
    return round(total, 4)
