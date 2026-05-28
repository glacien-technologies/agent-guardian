"""N-version racing primitive (M2 Pattern 1).

Run several deliberately-different attempts concurrently and take the first one
that produces a *validated* success — then cancel the losers. "Validated" means
a PoV-passing result (Pattern 2), never just "the coroutine returned"; racing is
only meaningful when success is defined by a reproducible oracle.

This generic ``race_first_success`` is the shared engine for both N-version
strategy racing (Pattern 1) and parallel-model racing (Pattern 4 — see
``core/model_race.py``).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

__all__ = ["RaceOutcome", "race_first_success"]

_LOG = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(frozen=True)
class RaceOutcome(Generic[T]):
    """Result of a first-success-wins race."""

    winner: T | None
    winner_label: str | None
    completed: int
    cancelled: int
    errors: int


async def race_first_success(
    factories: dict[str, Callable[[], Awaitable[T]]],
    validator: Callable[[T], Awaitable[bool] | bool],
) -> RaceOutcome[T]:
    """Run all ``factories`` concurrently; first result passing ``validator`` wins.

    ``factories`` maps a label (strategy id / model name) to a no-arg coroutine
    factory. As each task completes its result is validated; the first to pass
    wins and the remaining tasks are cancelled. A task that raises is counted as
    an error and does not win. If none pass, ``winner`` is ``None``.
    """
    if not factories:
        return RaceOutcome(None, None, 0, 0, 0)

    tasks: dict[asyncio.Task[T], str] = {}
    for label, factory in factories.items():
        task = asyncio.ensure_future(factory())
        tasks[task] = label

    completed = errors = 0
    winner: T | None = None
    winner_label: str | None = None
    pending = set(tasks)
    found = False
    try:
        while pending and not found:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                label = tasks[task]
                if task.cancelled():  # pragma: no cover — defensive
                    continue
                exc = task.exception()
                if exc is not None:
                    errors += 1
                    _LOG.debug("race: %s raised %s: %s", label, type(exc).__name__, exc)
                    continue
                completed += 1
                result = task.result()
                verdict = validator(result)
                ok = await verdict if asyncio.iscoroutine(verdict) else verdict
                if ok:
                    winner, winner_label = result, label
                    found = True
                    _LOG.info("race: %s won (validated)", label)
                    break
    finally:
        cancelled = 0
        for task in tasks:
            if not task.done():
                task.cancel()
                cancelled += 1
        # Drain cancellations so they don't leak warnings.
        if cancelled:
            await asyncio.gather(*[t for t in tasks if not t.done()], return_exceptions=True)

    return RaceOutcome(
        winner=winner,
        winner_label=winner_label,
        completed=completed,
        cancelled=cancelled,
        errors=errors,
    )
