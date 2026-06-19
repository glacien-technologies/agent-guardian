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
import contextvars
import logging
import random
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import TypeVar

from agent_guardian.llm.errors import (
    LLMBudgetExceededError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMTransientError,
)

__all__ = [
    "AGENT_LOOP_MAX_RETRIES",
    "AGENT_LOOP_MAX_SECONDS",
    "DEFAULT_LLM_RETRY_CAP",
    "RetryTally",
    "compute_delay",
    "current_retry_tally",
    "retry_tally_scope",
    "with_backoff",
]

_LOG = logging.getLogger(__name__)

T = TypeVar("T")


# rc38 P0-#5 (#263) — aggregate retry-exhaustion signal. Per-call the retry
# layer already logs one WARNING when a call's retries are exhausted, but the
# operator has no SCAN-WIDE signal: was it one unlucky 429, or did 30% of all
# LLM calls give up? The tally below counts (a) every ``with_backoff`` call and
# (b) the subset whose retries were exhausted, so the swarm can emit ONE
# CLI-level WARNING at finalise when the exhausted ratio crosses a threshold.
#
# It is held in a ``ContextVar`` (not a module global) so concurrent scans /
# unit tests never bleed counts into each other: each scan enters
# ``retry_tally_scope()`` which installs a fresh tally for the duration of the
# scan and restores the previous binding on exit.


@dataclass
class RetryTally:
    """Scan-scoped counter of LLM calls and retry-exhausted calls.

    ``total`` is incremented once per :func:`with_backoff` invocation (i.e.
    per logical LLM call, regardless of how many retries it made). ``exhausted``
    is incremented when a call burned through every retry and still failed.
    """

    total: int = 0
    exhausted: int = 0

    def record_call(self) -> None:
        self.total += 1

    def record_exhausted(self) -> None:
        self.exhausted += 1

    @property
    def exhausted_ratio(self) -> float:
        """Fraction of calls whose retries were exhausted (0.0 when no calls)."""
        if self.total <= 0:
            return 0.0
        return self.exhausted / self.total


# When no scope is active the tally is ``None`` and ``with_backoff`` simply
# skips counting — the per-call WARNING is unaffected, only the aggregate is.
_RETRY_TALLY: contextvars.ContextVar[RetryTally | None] = contextvars.ContextVar(
    "agent_guardian_retry_tally", default=None
)


def current_retry_tally() -> RetryTally | None:
    """Return the tally bound to the current scope, or ``None`` outside a scope."""
    return _RETRY_TALLY.get()


@contextlib.contextmanager
def retry_tally_scope(tally: RetryTally | None = None) -> Iterator[RetryTally]:
    """Bind a fresh :class:`RetryTally` for the duration of the ``with`` block.

    Restores the previous binding on exit so nested / sequential scans (and
    unit tests) never leak counts. Pass an explicit ``tally`` to share an
    instance the caller already holds; otherwise a fresh one is created.
    """
    active = tally if tally is not None else RetryTally()
    token = _RETRY_TALLY.set(active)
    try:
        yield active
    finally:
        _RETRY_TALLY.reset(token)


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

# QA-008 — public ``with_backoff`` retry ceiling, lowered from the legacy 6.
# With base=1s, factor=2, max=60s the legacy ceiling soaked up to ~63s of
# wallclock for a single LLM call when a provider entered a hard 5xx /
# timeout cycle; combined with a 300s scan-wide budget that cascade could
# blow the budget by 50%+ before the swarm-level guillotine tripped.
# 3 retries (≈1+2+4 ≈ 7s) bounds the aggregate per-call worst case while
# still absorbing typical transient blips. Callers that genuinely need
# 6 retries (e.g. mcp transport with long-tail provider quirks) pass
# ``max_retries=`` explicitly.
DEFAULT_LLM_RETRY_CAP = 3


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
                # what to do based on ``cancel_event.is_set()``. We assign
                # the awaited result to ``_`` so static analysis doesn't flag
                # the await as an ineffectual expression statement.
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    _ = await pending_task
    return not cancel_event.is_set()


async def with_backoff(
    coro_factory: Callable[[], Awaitable[T]],
    *,
    base_seconds: float = 1.0,
    factor: float = 2.0,
    jitter_pct: float = 0.25,
    max_seconds: float = 60.0,
    max_retries: int = DEFAULT_LLM_RETRY_CAP,
    retry_on: tuple[type[Exception], ...] = _DEFAULT_RETRY_ON,
    rng: random.Random | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    cancel_event: asyncio.Event | None = None,
    deadline_monotonic: float | None = None,
    scan_start_monotonic: float | None = None,
    budget_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
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

    QA-008 wall-budget guillotine
    -----------------------------
    When ``deadline_monotonic`` is supplied (an absolute ``time.monotonic()``
    timestamp), the helper checks the clock before each attempt and before
    each backoff sleep. If the clock has already passed the deadline, or
    the *computed* sleep would push us past it, we raise
    :class:`LLMBudgetExceededError` immediately instead of sleeping or
    starting another attempt. ``scan_start_monotonic`` and
    ``budget_seconds`` are accepted as a convenience for callers who carry
    the start time and budget separately; passing both is equivalent to
    ``deadline_monotonic=scan_start + budget_seconds``. ``monotonic`` is
    injectable for deterministic tests.

    The guillotine deliberately raises a non-retryable error so any
    *outer* retry wrapper does NOT re-enter the cascade. The most recent
    retryable exception is attached as ``LLMBudgetExceededError.cause``
    so the operator can see what was failing when the budget tripped.
    """
    deadline = _resolve_deadline(
        deadline_monotonic=deadline_monotonic,
        scan_start_monotonic=scan_start_monotonic,
        budget_seconds=budget_seconds,
    )
    # rc38 P0-#5 (#263) — count this logical LLM call once toward the
    # scan-wide retry tally (no-op outside a ``retry_tally_scope``).
    tally = _RETRY_TALLY.get()
    if tally is not None:
        tally.record_call()
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        # Wall-budget pre-attempt check. We do this BEFORE the cancel-event
        # check so a scan that has blown its budget surfaces a precise
        # ``LLMBudgetExceededError`` rather than a generic CancelledError
        # if both fire on the same tick.
        if deadline is not None and monotonic() >= deadline:
            elapsed_at = _elapsed_for_log(scan_start_monotonic, monotonic)
            budget_at = _budget_for_log(budget_seconds, deadline, scan_start_monotonic)
            _LOG.warning(
                "retry budget guillotine before attempt %d: elapsed=%.2fs budget=%.2fs",
                attempt,
                elapsed_at,
                budget_at,
            )
            raise LLMBudgetExceededError(
                f"wall budget exhausted before attempt {attempt + 1}",
                elapsed=elapsed_at,
                budget=budget_at,
                cause=last_exc,
            )
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
                # rc38 P0-#5 (#263) — feed the scan-wide tally so the swarm
                # can emit one aggregate ">N% of calls exhausted retries"
                # WARNING at finalise.
                if tally is not None:
                    tally.record_exhausted()
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
            # Wall-budget look-ahead. If the sleep would push us past the
            # deadline, refuse to sleep -- raise the guillotine now so the
            # operator's wall budget is honoured to within ~one attempt.
            if deadline is not None and monotonic() + delay >= deadline:
                elapsed_at = _elapsed_for_log(scan_start_monotonic, monotonic)
                budget_at = _budget_for_log(budget_seconds, deadline, scan_start_monotonic)
                _LOG.warning(
                    "retry budget guillotine mid-backoff after %d attempts "
                    "(would-sleep=%.2fs, elapsed=%.2fs, budget=%.2fs): %s: %s",
                    attempt + 1,
                    delay,
                    elapsed_at,
                    budget_at,
                    type(exc).__name__,
                    exc,
                )
                raise LLMBudgetExceededError(
                    f"wall budget would be exhausted by next backoff "
                    f"(elapsed={elapsed_at:.2f}s, budget={budget_at:.2f}s, "
                    f"would_sleep={delay:.2f}s)",
                    elapsed=elapsed_at,
                    budget=budget_at,
                    cause=exc,
                ) from exc
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


def _resolve_deadline(
    *,
    deadline_monotonic: float | None,
    scan_start_monotonic: float | None,
    budget_seconds: float | None,
) -> float | None:
    """Resolve the absolute monotonic deadline from the caller's args.

    Prefers an explicit ``deadline_monotonic``. Otherwise computes
    ``scan_start + budget`` when both are provided. Returns ``None`` when
    no budget was requested (the legacy no-guillotine path).
    """
    if deadline_monotonic is not None:
        return deadline_monotonic
    if scan_start_monotonic is not None and budget_seconds is not None:
        return scan_start_monotonic + budget_seconds
    return None


def _elapsed_for_log(
    scan_start_monotonic: float | None,
    monotonic: Callable[[], float],
) -> float:
    """Best-effort 'seconds since scan start' for the guillotine log line.

    Returns ``0.0`` when the caller passed a bare ``deadline_monotonic``
    without ``scan_start_monotonic`` -- the log line still records the
    budget overshoot, just without a phase-relative timestamp.
    """
    if scan_start_monotonic is None:
        return 0.0
    return max(0.0, monotonic() - scan_start_monotonic)


def _budget_for_log(
    budget_seconds: float | None,
    deadline: float,
    scan_start_monotonic: float | None,
) -> float:
    """Resolve the 'budget' figure to report in the guillotine log."""
    if budget_seconds is not None:
        return budget_seconds
    if scan_start_monotonic is not None:
        return max(0.0, deadline - scan_start_monotonic)
    return 0.0
