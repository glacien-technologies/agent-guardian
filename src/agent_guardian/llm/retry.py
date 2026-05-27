"""Exponential backoff with jitter (PRD §14.3).

Used by every provider client. The RNG is injectable so unit tests can pass
``random.Random(0)`` and assert deterministic delays.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from agent_guardian.llm.errors import (
    LLMRateLimitError,
    LLMTimeoutError,
    LLMTransientError,
)

__all__ = ["compute_delay", "with_backoff"]

_LOG = logging.getLogger(__name__)

T = TypeVar("T")

_DEFAULT_RETRY_ON: tuple[type[Exception], ...] = (
    LLMRateLimitError,
    LLMTransientError,
    LLMTimeoutError,
)


def compute_delay(
    attempt: int,
    *,
    base_seconds: float = 1.0,
    factor: float = 2.0,
    jitter_pct: float = 0.25,
    max_seconds: float = 60.0,
    rng: random.Random | None = None,
) -> float:
    """Return the delay (seconds) for the given 0-based retry ``attempt``.

    ``delay = clamp(base * factor**attempt, 0, max_seconds) * (1 + jitter)``
    where ``jitter`` is uniform in ``[-jitter_pct, +jitter_pct]``.
    """
    if attempt < 0:
        raise ValueError("attempt must be non-negative")
    if base_seconds < 0:
        raise ValueError("base_seconds must be non-negative")
    if factor < 1.0:
        raise ValueError("factor must be >= 1.0")
    if not 0.0 <= jitter_pct < 1.0:
        raise ValueError("jitter_pct must be in [0.0, 1.0)")

    rng = rng or random.Random()
    raw = min(base_seconds * (factor**attempt), max_seconds)
    jitter = rng.uniform(-jitter_pct, jitter_pct)
    return max(0.0, raw * (1.0 + jitter))


async def with_backoff(
    coro_factory: Callable[[], Awaitable[T]],
    *,
    base_seconds: float = 1.0,
    factor: float = 2.0,
    jitter_pct: float = 0.25,
    max_seconds: float = 60.0,
    max_retries: int = 6,
    retry_on: tuple[type[Exception], ...] = _DEFAULT_RETRY_ON,
    rng: random.Random | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Call ``coro_factory()`` with exponential backoff on retryable errors.

    Honours :attr:`LLMRateLimitError.retry_after` if present — overrides the
    computed backoff for that single retry.

    Stops after ``max_retries`` retries (so up to ``max_retries + 1`` attempts).
    Non-retryable exceptions are re-raised immediately.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await coro_factory()
        except retry_on as exc:
            last_exc = exc
            if attempt >= max_retries:
                _LOG.warning(
                    "retry exhausted after %d attempts: %s: %s",
                    attempt + 1,
                    type(exc).__name__,
                    exc,
                )
                break
            retry_after = getattr(exc, "retry_after", None)
            if isinstance(retry_after, int | float) and retry_after >= 0:
                delay = float(retry_after)
            else:
                delay = compute_delay(
                    attempt,
                    base_seconds=base_seconds,
                    factor=factor,
                    jitter_pct=jitter_pct,
                    max_seconds=max_seconds,
                    rng=rng,
                )
            _LOG.warning(
                "retry %d/%d (%s: %s) — backoff %.2fs",
                attempt + 1,
                max_retries,
                type(exc).__name__,
                exc,
                delay,
            )
            await sleep(delay)
    assert last_exc is not None  # invariant: only reachable after a retryable raise
    raise last_exc
