"""Core scoring, tiering, and budget primitives for AgentGuardian."""

from agent_guardian.core.budget import (
    DEFAULT_SLICE_ALLOCATIONS,
    BudgetController,
    BudgetSlice,
)
from agent_guardian.core.scoring import (
    AIVSS_FORMULA_VERSION,
    SEVERITY_WEIGHTS,
    SUB_SCORE_MAP,
    TIER_WEIGHTS,
    AivssResult,
    apply_penalty,
    asi_score,
    compute_aivss,
    fail_rate,
    pass_rate,
    sub_scores,
    tier_weighted_aggregate,
)
from agent_guardian.core.tiering import detect_tier

__all__ = [
    "AIVSS_FORMULA_VERSION",
    "DEFAULT_SLICE_ALLOCATIONS",
    "SEVERITY_WEIGHTS",
    "SUB_SCORE_MAP",
    "TIER_WEIGHTS",
    "AivssResult",
    "BudgetController",
    "BudgetSlice",
    "apply_penalty",
    "asi_score",
    "compute_aivss",
    "detect_tier",
    "fail_rate",
    "pass_rate",
    "sub_scores",
    "tier_weighted_aggregate",
]
