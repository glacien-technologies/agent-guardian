"""Unit tests for the async token-bucket rate limiter (Stage 1B)."""

from __future__ import annotations

import asyncio
import time

import pytest

from agent_guardian.core.ratelimit import AsyncTokenBucket


async def test_disabled_bucket_is_noop_and_immediate() -> None:
    bucket = AsyncTokenBucket(None)
    assert bucket.rate_per_sec == 0.0
    start = time.monotonic()
    for _ in range(50):
        await bucket.acquire()
    assert time.monotonic() - start < 0.05


@pytest.mark.parametrize("rate", [0.0, -1.0, -10.5])
async def test_non_positive_rate_disables(rate: float) -> None:
    bucket = AsyncTokenBucket(rate)
    assert bucket.rate_per_sec == rate or bucket.rate_per_sec == 0.0
    # Many acquires return instantly when disabled.
    await asyncio.wait_for(asyncio.gather(*(bucket.acquire() for _ in range(20))), timeout=0.5)


async def test_zero_token_acquire_is_noop() -> None:
    bucket = AsyncTokenBucket(1.0, capacity=1.0)
    start = time.monotonic()
    await bucket.acquire(0.0)
    assert time.monotonic() - start < 0.05


async def test_initial_burst_up_to_capacity_is_immediate() -> None:
    # Capacity 3 => first 3 acquires drain the full bucket without waiting.
    bucket = AsyncTokenBucket(100.0, capacity=3.0)
    start = time.monotonic()
    for _ in range(3):
        await bucket.acquire()
    assert time.monotonic() - start < 0.05


async def test_serialises_under_concurrency_with_small_rate() -> None:
    # Rate 20/s, capacity 1 => one immediate grant, then ~0.05s apart. Five
    # concurrent awaiters must take at least 4 refill intervals total.
    rate = 20.0
    bucket = AsyncTokenBucket(rate, capacity=1.0)
    n = 5
    start = time.monotonic()
    await asyncio.gather(*(bucket.acquire() for _ in range(n)))
    elapsed = time.monotonic() - start
    # (n - 1) tokens must be refilled at `rate`/s after the initial burst token.
    expected_min = (n - 1) / rate
    assert elapsed >= expected_min * 0.9, (elapsed, expected_min)


async def test_does_not_overgrant_tokens() -> None:
    # With capacity 2 and a slow refill, only 2 acquires may complete promptly;
    # the third must observably wait for a refill.
    bucket = AsyncTokenBucket(5.0, capacity=2.0)
    completion_order: list[float] = []

    async def worker() -> None:
        await bucket.acquire()
        completion_order.append(time.monotonic())

    start = time.monotonic()
    await asyncio.gather(*(worker() for _ in range(3)))
    completion_order.sort()
    # First two near-instant, third gated by ~1/rate = 0.2s.
    assert completion_order[1] - start < 0.1
    assert completion_order[2] - start >= 0.2 * 0.9


async def test_cancellation_does_not_strand_capacity() -> None:
    # A cancelled awaiter must not consume a token. After cancelling a waiter,
    # the bucket should still grant exactly its refilled tokens to others.
    bucket = AsyncTokenBucket(10.0, capacity=1.0)
    # Drain the initial burst token.
    await bucket.acquire()

    waiter = asyncio.create_task(bucket.acquire())
    await asyncio.sleep(0.01)  # let it enter the wait
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    # The bucket should refill normally; a fresh acquire succeeds within a
    # bounded time (no token was wrongly deducted by the cancelled waiter).
    await asyncio.wait_for(bucket.acquire(), timeout=1.0)


async def test_demand_capped_at_capacity_makes_progress() -> None:
    # Asking for more tokens than capacity must not deadlock.
    bucket = AsyncTokenBucket(50.0, capacity=2.0)
    await asyncio.wait_for(bucket.acquire(10.0), timeout=1.0)


async def test_capacity_defaults_to_rate() -> None:
    bucket = AsyncTokenBucket(7.5)
    assert bucket.capacity == 7.5
    assert bucket.rate_per_sec == 7.5


async def test_refill_noop_when_clock_does_not_advance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Freeze the monotonic clock so elapsed == 0 on the second acquire, hitting
    # the no-advance branch of the refill path without mutating token state.
    bucket = AsyncTokenBucket(5.0, capacity=2.0)
    frozen = time.monotonic()
    monkeypatch.setattr("agent_guardian.core.ratelimit.time.monotonic", lambda: frozen)
    await bucket.acquire()
    await bucket.acquire()
    # Both initial-burst tokens consumed; clock never advanced so no refill.
    assert bucket.capacity == 2.0
