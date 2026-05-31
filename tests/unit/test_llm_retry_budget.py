"""Regression tests for QA-008 — wall-budget guillotine in ``with_backoff``.

Each test below fails on ``main`` (no ``LLMBudgetExceededError``, no
``deadline_monotonic`` kwarg, default ``max_retries`` is 6) and passes after
the QA-008 fix lands. The goal is to lock in three properties:

1. The default retry cap is now 3 (the QA-008 ``--llm-retry-cap`` default).
2. When ``deadline_monotonic`` is set and the clock has passed it,
   ``with_backoff`` raises ``LLMBudgetExceededError`` BEFORE the next attempt
   and BEFORE sleeping.
3. When the *next* backoff would push past the deadline, the look-ahead
   refuses to sleep and raises the guillotine immediately (this is the
   actual QA-008 production cascade: a 16s sleep was about to fire with
   2s of budget left).
4. The error carries elapsed / budget / cause so the operator can see
   why the budget blew (the last retryable exception is preserved).
5. The legacy no-deadline path is unchanged (backwards compat).
"""

from __future__ import annotations

import asyncio
import random
from itertools import count

import pytest

from agent_guardian.llm.errors import (
    LLMBudgetExceededError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import (
    DEFAULT_LLM_RETRY_CAP,
    with_backoff,
)


def test_default_retry_cap_is_three_qa_008() -> None:
    """Default ``with_backoff`` retries dropped from 6 → 3 to bound the cascade.

    QA-008 acceptance: a single LLM call's worst-case backoff aggregate must
    fit comfortably under the smallest typical scan budget. 3 retries with
    base=1, factor=2 ≈ 1+2+4 = 7s aggregate, vs the legacy 6 ≈ 63s.
    """
    assert DEFAULT_LLM_RETRY_CAP == 3


async def test_with_backoff_guillotine_pre_attempt() -> None:
    """When the deadline is already in the past on entry, raise immediately."""
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        return "never"

    async def fake_sleep(_s: float) -> None:
        pytest.fail("sleep must not be called when budget already blown")

    # Deterministic clock: t=100 at "now"; deadline already 1s in the past.
    fake_clock = iter(count(100))

    def now() -> float:
        return float(next(fake_clock))

    with pytest.raises(LLMBudgetExceededError) as exc_info:
        await with_backoff(
            coro,
            sleep=fake_sleep,
            rng=random.Random(0),
            deadline_monotonic=99.0,
            scan_start_monotonic=0.0,
            budget_seconds=99.0,
            monotonic=now,
        )
    # No attempts may run when the budget was blown before the first call.
    assert calls == 0
    # Cause is None: nothing failed yet to attribute the budget death to.
    assert exc_info.value.cause is None
    assert exc_info.value.budget == pytest.approx(99.0)


async def test_with_backoff_guillotine_mid_backoff_look_ahead() -> None:
    """The would-sleep look-ahead refuses to sleep past the deadline.

    Reproduces the QA-008 cascade: an LLM call fails transiently, the next
    computed backoff is 16s, but only 2s of wall budget remains. The fix
    must NOT call sleep — it must raise the guillotine immediately and
    attach the upstream transient as ``cause``.
    """
    calls = 0
    sleeps: list[float] = []

    async def coro() -> str:
        nonlocal calls
        calls += 1
        raise LLMTimeoutError("gemini: timeout")

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    # Clock advances 1s per read so the look-ahead has stable input.
    fake_clock = iter([0.0, 0.5, 1.0, 1.5, 2.0])

    def now() -> float:
        return next(fake_clock)

    with pytest.raises(LLMBudgetExceededError) as exc_info:
        await with_backoff(
            coro,
            base_seconds=16.0,  # forces the first computed backoff to >> remaining
            factor=2.0,
            jitter_pct=0.0,
            max_seconds=60.0,
            max_retries=5,
            sleep=fake_sleep,
            rng=random.Random(0),
            scan_start_monotonic=0.0,
            budget_seconds=2.0,
            monotonic=now,
        )
    # We made the first attempt (it raised LLMTimeoutError), then the
    # look-ahead refused to sleep and raised the guillotine -- no sleeps.
    assert calls == 1
    assert sleeps == []
    # Upstream cause is preserved for the operator-facing log line.
    assert isinstance(exc_info.value.cause, LLMTimeoutError)
    assert "gemini: timeout" in str(exc_info.value.cause)
    assert exc_info.value.budget == pytest.approx(2.0)


async def test_budget_exceeded_is_not_a_timeout_subclass() -> None:
    """Catching ``LLMTimeoutError`` MUST NOT swallow ``LLMBudgetExceededError``.

    If an outer ``with_backoff`` wrapper or call-site treats budget-exceeded
    as just-another-timeout, the cascade is back. Lock the disjoint
    hierarchy.
    """
    assert not issubclass(LLMBudgetExceededError, LLMTimeoutError)
    assert not issubclass(LLMBudgetExceededError, LLMTransientError)


async def test_with_backoff_no_deadline_is_legacy_path() -> None:
    """Omitting the deadline kwargs preserves the pre-QA-008 behaviour."""
    calls = 0
    sleeps: list[float] = []

    async def coro() -> str:
        nonlocal calls
        calls += 1
        if calls < 2:
            raise LLMTransientError("blip")
        return "ok"

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    result = await with_backoff(
        coro,
        base_seconds=1.0,
        factor=2.0,
        jitter_pct=0.0,
        sleep=fake_sleep,
        rng=random.Random(0),
    )
    assert result == "ok"
    assert calls == 2
    assert sleeps == [pytest.approx(1.0)]


async def test_with_backoff_deadline_in_future_succeeds() -> None:
    """A deadline comfortably in the future does NOT interfere with success."""
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        if calls < 2:
            raise LLMTransientError("blip")
        return "ok"

    async def fake_sleep(_s: float) -> None:
        return None

    # Generous budget that the (fake-sleep, near-instant) flow cannot blow.
    fake_clock = iter(count(0))

    def now() -> float:
        return float(next(fake_clock))

    result = await with_backoff(
        coro,
        base_seconds=1.0,
        factor=2.0,
        jitter_pct=0.0,
        max_retries=3,
        sleep=fake_sleep,
        rng=random.Random(0),
        scan_start_monotonic=0.0,
        budget_seconds=10_000.0,
        monotonic=now,
    )
    assert result == "ok"
    assert calls == 2


async def test_with_backoff_explicit_deadline_monotonic_wins() -> None:
    """Passing ``deadline_monotonic`` overrides the convenience pair."""
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        return "never"

    async def fake_sleep(_s: float) -> None:
        pytest.fail("must not sleep when explicit deadline is in the past")

    def now() -> float:
        return 500.0

    with pytest.raises(LLMBudgetExceededError):
        await with_backoff(
            coro,
            sleep=fake_sleep,
            rng=random.Random(0),
            # Explicit deadline 100s ago -> guillotine fires regardless of
            # the (very generous) scan_start/budget pair.
            deadline_monotonic=400.0,
            scan_start_monotonic=0.0,
            budget_seconds=9_999.0,
            monotonic=now,
        )
    assert calls == 0


async def test_with_backoff_cancel_still_works_alongside_deadline() -> None:
    """A cancel_event mid-backoff still raises the upstream retryable exc.

    The deadline check must not break QA-002 / EARLY_STOP semantics.
    """
    cancel = asyncio.Event()
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        raise LLMTransientError("blip")

    async def fake_sleep(_s: float) -> None:
        cancel.set()
        await asyncio.sleep(0)

    def now() -> float:
        # Plenty of budget left -- this test is about cancel, not budget.
        return 0.0

    with pytest.raises(LLMTransientError):
        await with_backoff(
            coro,
            max_retries=5,
            sleep=fake_sleep,
            rng=random.Random(0),
            cancel_event=cancel,
            scan_start_monotonic=0.0,
            budget_seconds=10_000.0,
            monotonic=now,
        )
    assert calls == 1
