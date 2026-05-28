"""Epoch-based work scheduler (M2 Pattern 9).

ATLANTIS-style: each epoch re-prioritizes work items by
``score / estimated_remaining_cost`` (expected value per dollar) and demotes
items that have failed repeatedly — mirroring ATLANTIS-C's TASKSCHEDULER
switching away from unstable strategies on repeated failure.

This is pure ordering logic — no LLM, no clock side-effects beyond the epoch
counter — so the Commander can consult it to decide what to run next without
the scheduler owning execution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

__all__ = ["EpochScheduler", "ScheduledItem"]

_LOG = logging.getLogger(__name__)


@dataclass
class ScheduledItem:
    """One unit of schedulable work (a scenario / strategy instance)."""

    item_id: str
    score: float = 0.5
    """Cheap-classifier expected-value score in [0, 1] (Pattern 3 feeds this)."""
    est_cost_usd: float = 0.05
    failures: int = 0
    done: bool = False

    def value_density(self) -> float:
        """Expected value per dollar — the scheduling key."""
        return self.score / self.est_cost_usd if self.est_cost_usd > 0 else float("inf")


class EpochScheduler:
    """Re-prioritizes work each epoch; demotes repeatedly-failing items."""

    def __init__(self, *, epoch_seconds: float = 1200.0, failure_demotion: int = 2) -> None:
        if epoch_seconds <= 0:
            raise ValueError("epoch_seconds must be positive")
        self._epoch_seconds = epoch_seconds
        self._failure_demotion = failure_demotion
        self._epoch = 0
        self._items: dict[str, ScheduledItem] = {}

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def epoch_seconds(self) -> float:
        return self._epoch_seconds

    def add(self, item: ScheduledItem) -> None:
        self._items[item.item_id] = item

    def record_failure(self, item_id: str) -> None:
        item = self._items.get(item_id)
        if item is not None:
            item.failures += 1
            _LOG.debug("scheduler: item %s failure #%d", item_id, item.failures)

    def record_success(self, item_id: str) -> None:
        item = self._items.get(item_id)
        if item is not None:
            item.done = True

    def advance_epoch(self) -> int:
        self._epoch += 1
        return self._epoch

    def prioritized(self) -> list[ScheduledItem]:
        """Active items ordered for this epoch.

        Sort key: items at/over the failure-demotion threshold sink to the
        back; within each band, higher value-density (score/cost) runs first.
        Done items are excluded.
        """
        active = [it for it in self._items.values() if not it.done]
        return sorted(
            active,
            key=lambda it: (it.failures >= self._failure_demotion, -it.value_density()),
        )

    def next_item(self) -> ScheduledItem | None:
        ordered = self.prioritized()
        return ordered[0] if ordered else None
