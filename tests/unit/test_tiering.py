"""Truth-table tests for detect_tier (PRD §6.3)."""

from __future__ import annotations

import pytest

from agent_guardian.core.tiering import detect_tier
from agent_guardian.models.tier import ObservedSurface, Tier


@pytest.mark.parametrize(
    ("has_tools", "has_memory", "touches_pii", "is_multi_agent", "expected"),
    [
        # 16 truth-table combinations across 4 bits.
        (True, True, True, True, Tier.T1_CRITICAL),
        (True, True, True, False, Tier.T1_CRITICAL),
        (True, True, False, True, Tier.T2_HIGH),
        (True, True, False, False, Tier.T2_HIGH),
        (True, False, True, True, Tier.T2_HIGH),
        (True, False, True, False, Tier.T3_STANDARD),
        (True, False, False, True, Tier.T2_HIGH),
        (True, False, False, False, Tier.T3_STANDARD),
        (False, True, True, True, Tier.T3_STANDARD),
        (False, True, True, False, Tier.T3_STANDARD),
        (False, True, False, True, Tier.T3_STANDARD),
        (False, True, False, False, Tier.T3_STANDARD),
        (False, False, True, True, Tier.T4_LOW),
        (False, False, True, False, Tier.T4_LOW),
        (False, False, False, True, Tier.T4_LOW),
        (False, False, False, False, Tier.T4_LOW),
    ],
)
def test_detect_tier_truth_table(
    has_tools: bool,
    has_memory: bool,
    touches_pii: bool,
    is_multi_agent: bool,
    expected: Tier,
) -> None:
    surface = ObservedSurface(
        has_tools=has_tools,
        has_memory=has_memory,
        touches_pii=touches_pii,
        is_multi_agent=is_multi_agent,
    )
    assert detect_tier(surface) is expected


def test_detect_tier_is_pure_no_io() -> None:
    """Same input twice yields same output (no clock, no RNG)."""
    surface = ObservedSurface(
        has_tools=True, has_memory=True, touches_pii=True, is_multi_agent=False
    )
    assert detect_tier(surface) is detect_tier(surface)
