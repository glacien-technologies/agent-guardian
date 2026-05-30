"""Exponential backoff with jitter (PRD §14.3).

Used by every provider client. The RNG is injectable so unit tests can pass
``random.Random(0)`` and assert deterministic delays.

The agent-loop path uses tighter defaults than the public ``with_backoff``
ceiling: an attacker that hits a 503 cycle during a Commander early-stop should
exit within seconds, not soak the wall-clock budget for minutes. The
``cancel_event``-aware sleep helper interrupts the backoff promptly when a
cancellation signal fires.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from agent_guardian.llm.errors import (
    LLMRateLimitError,
    LLMTimeoutError,
    LLMTransientError,
)

__all__ = [
    "AGENT_LOOP_MAX_RETRIES",
    "AGENT_LOOP_MAX_SECONDS",
    "compute_delay",
    "with_backoff",
]

_LOG = logging.getLogger(__name__)

T = TypeVar("T")

_DEFAULT_RETRY_ON: tuple[type[Exception], ...] = (
    LLMRateLimitError,
    LLMTransientError,
    LLMTimeoutError,
)

# Agent-loop defaults. The public ``with_backoff`` ceiling (60s cap, up to 6
# retries) is appropriate for one-off provider calls but turns a single 503
# cycle into a multi-minute soak when an attacker is iterating turns and the
# Commander has already signalled EARLY_STOP. The agent loop uses these
# tighter numbers (~15s max delay per attempt, 3 retries) so a cancellation
# interrupts within seconds rather than minutes.
AGENT_LOOP_MAX_RETRIES = 3
AGENT_LOOP_MAX_SECONDS = 15.0


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


async def _wrap_sleep(delay: float, sleep: Callable[[float], Awaitable[None]]) -> None:
    """Tiny coroutine that ``await``s the injected sleep callable.

    Needed because ``asyncio.create_task`` expects a coroutine, not the
    bare ``Awaitable[None]`` the ``sleep`` parameter is typed as (tests
    inject a generic awaitable for deterministic delays).
    """
    await sleep(delay)


async def _interruptible_sleep(
    delay: float,
    *,
    cancel_event: asyncio.Event | None,
    sleep: Callable[[float], Awaitable[None]],
) -> bool:
    """Sleep for ``delay`` seconds, returning early when ``cancel_event`` fires.

    Returns ``True`` when the full delay elapsed (i.e. no cancellation), and
    ``False`` when the cancel event was set during the wait. When
    ``cancel_event`` is ``None`` this is just ``await sleep(delay)`` and the
    return is always ``True``. When the cancel event is already set on entry
    the helper returns immediately without sleeping.
    """
    if cancel_event is None:
        await sleep(delay)
        return True
    if cancel_event.is_set():
        return False
    # Race the sleep against the cancellation signal so an EARLY_STOP fires
    # promptly even mid-backoff. We deliberately do NOT call ``cancel()`` on
    # the sleep task -- ``asyncio.wait(FIRST_COMPLETED)`` returns as soon as
    # either side resolves and the pending sleep is cancelled cleanly below.
    sleep_task: asyncio.Task[None] = asyncio.create_task(_wrap_sleep(delay, sleep))
    cancel_task: asyncio.Task[bool] = asyncio.create_task(cancel_event.wait())
    try:
        await asyncio.wait(
            {sleep_task, cancel_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        for pending_task in (sleep_task, cancel_task):
            if not pending_task.done():
                pending_task.cancel()
                # Cancelled / pending sleep failure is expected; suppress
                # so cleanup never raises. The caller has already decided
                # what to do based on ``cancel_event.is_set()``.
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await pending_task
    return not cancel_event.is_set()


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
    cancel_event: asyncio.Event | None = None,
) -> T:
    """Call ``coro_factory()`` with exponential backoff on retryable errors.

    Honours :attr:`LLMRateLimitError.retry_after` if present — overrides the
    computed backoff for that single retry.

    Stops after ``max_retries`` retries (so up to ``max_retries + 1`` attempts).
    Non-retryable exceptions are re-raised immediately.

    When ``cancel_event`` is supplied the sleep between attempts races against
    the event so Commander early-stop interrupts a long backoff within
    seconds. On cancellation we re-raise the last retryable exception
    immediately rather than starting a fresh attempt, so the caller can see
    "we gave up because we were asked to stop".
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        if cancel_event is not None and cancel_event.is_set():
            if last_exc is not None:
                _LOG.info(
                    "retry cancelled after %d attempts: %s: %s",
                    attempt,
                    type(last_exc).__name__,
                    last_exc,
                )
                raise last_exc
            # No prior failure to surface; propagate as cancelled error so the
            # caller can distinguish "asked to stop before first attempt".
            raise asyncio.CancelledError("with_backoff cancelled before first attempt")
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
            completed = await _interruptible_sleep(delay, cancel_event=cancel_event, sleep=sleep)
            if not completed:
                # Early-stop fired mid-backoff. Re-raise the most recent
                # retryable error rather than spin up another attempt.
                _LOG.info(
                    "retry cancelled mid-backoff after %d attempts: %s: %s",
                    attempt + 1,
                    type(exc).__name__,
                    exc,
                )
                raise exc
    assert last_exc is not None  # invariant: only reachable after a retryable raise
    raise last_exc
