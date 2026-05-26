"""Budget allocation, donation, and exhaustion tests."""

from __future__ import annotations

import pytest

from agent_guardian.core.budget import (
    DEFAULT_SLICE_ALLOCATIONS,
    BudgetController,
)


def test_default_allocations_sum_to_two_million() -> None:
    assert sum(DEFAULT_SLICE_ALLOCATIONS.values()) == 2_000_000


def test_default_controller_initialises_every_agent() -> None:
    ctrl = BudgetController()
    for agent in DEFAULT_SLICE_ALLOCATIONS:
        slice_ = ctrl.slice_for(agent)
        assert slice_.tokens_remaining == DEFAULT_SLICE_ALLOCATIONS[agent]


def test_total_remaining_starts_at_allocated_sum() -> None:
    ctrl = BudgetController()
    assert ctrl.total_remaining() == 2_000_000
    assert ctrl.total_spent() == 0


def test_request_consumes_tokens() -> None:
    ctrl = BudgetController()
    assert ctrl.request("recon", 10_000) is True
    assert ctrl.slice_for("recon").tokens_remaining == 40_000
    assert ctrl.total_spent() == 10_000


def test_request_returns_false_when_slice_exhausted() -> None:
    ctrl = BudgetController()
    assert ctrl.request("recon", 50_000) is True
    assert ctrl.request("recon", 1) is False
    assert ctrl.slice_for("recon").tokens_remaining == 0


def test_request_rejects_negative_amount() -> None:
    ctrl = BudgetController()
    with pytest.raises(ValueError):
        ctrl.request("recon", -1)


def test_request_unknown_agent_raises_key_error() -> None:
    ctrl = BudgetController()
    with pytest.raises(KeyError):
        ctrl.request("ghost", 100)


def test_donate_moves_tokens_between_agents() -> None:
    ctrl = BudgetController()
    ctrl.donate("commander", "asi01", 25_000)
    assert ctrl.slice_for("commander").tokens_remaining == 75_000
    assert ctrl.slice_for("asi01").tokens_remaining == 175_000


def test_donate_rejects_overcommit() -> None:
    ctrl = BudgetController()
    with pytest.raises(ValueError):
        ctrl.donate("commander", "asi01", 10_000_000)


def test_donate_rejects_negative_amount() -> None:
    ctrl = BudgetController()
    with pytest.raises(ValueError):
        ctrl.donate("commander", "asi01", -100)


def test_donate_unknown_agent_raises_key_error() -> None:
    ctrl = BudgetController()
    with pytest.raises(KeyError):
        ctrl.donate("ghost", "asi01", 100)
    with pytest.raises(KeyError):
        ctrl.donate("asi01", "ghost", 100)


def test_custom_allocations_respected() -> None:
    ctrl = BudgetController(
        total_tokens=1_000,
        wall_seconds=10.0,
        allocations={"a": 400, "b": 600},
    )
    assert ctrl.slice_for("a").tokens_remaining == 400
    assert ctrl.slice_for("b").tokens_remaining == 600
    assert ctrl.total_remaining() == 1_000


def test_oversubscribed_allocations_raise() -> None:
    with pytest.raises(ValueError):
        BudgetController(total_tokens=100, allocations={"a": 200})


def test_negative_total_tokens_raises() -> None:
    with pytest.raises(ValueError):
        BudgetController(total_tokens=-1)


def test_negative_wall_seconds_raises() -> None:
    with pytest.raises(ValueError):
        BudgetController(wall_seconds=-1.0)


def test_negative_allocation_value_raises() -> None:
    with pytest.raises(ValueError):
        BudgetController(total_tokens=100, allocations={"a": -10})


def test_total_spent_tracks_requests_and_donations() -> None:
    ctrl = BudgetController(
        total_tokens=1_000,
        wall_seconds=10.0,
        allocations={"a": 400, "b": 600},
    )
    ctrl.request("a", 100)
    assert ctrl.total_spent() == 100
    ctrl.donate("b", "a", 50)
    # Donation doesn't change total — only requests do.
    assert ctrl.total_spent() == 100
    assert ctrl.total_remaining() == 900


def test_wall_seconds_distributed_proportionally() -> None:
    ctrl = BudgetController(
        total_tokens=1_000,
        wall_seconds=100.0,
        allocations={"a": 400, "b": 600},
    )
    assert ctrl.slice_for("a").wall_seconds_remaining == pytest.approx(40.0)
    assert ctrl.slice_for("b").wall_seconds_remaining == pytest.approx(60.0)
