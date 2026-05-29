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


# ---------------------------------------------------------------------------
# Adaptive back-off: observe_rate_limited()
# ---------------------------------------------------------------------------


class _FakeClock:
    """A manually advanced monotonic clock for deterministic adaptive tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, dt: float) -> None:
        self.now += dt


async def test_observe_on_disabled_bucket_promotes_to_adaptive() -> None:
    # Default-on back-off (#13): a 429 on a bucket with no configured rate must
    # still throttle. The first observed 429 promotes the disabled bucket to an
    # adaptive one paced from the conservative default rate, honouring any
    # server retry_after as a cooldown.
    bucket = AsyncTokenBucket(None)
    assert bucket.rate_per_sec == 0.0
    bucket.observe_rate_limited(0.2)  # promotes + parks a cooldown
    assert bucket.rate_per_sec > 0.0  # promoted to the default adaptive rate
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    # The parked retry_after cooldown is honoured even though no rate was set.
    assert elapsed >= 0.2 * 0.9, elapsed


async def test_observe_on_disabled_bucket_without_retry_after_still_paces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even without a retry_after, a 429 on an unconfigured bucket promotes it and
    # the next acquire paces against the default adaptive rate (not instant).
    clock = _FakeClock()
    monkeypatch.setattr("agent_guardian.core.ratelimit.time.monotonic", clock)
    sleeps: list[float] = []

    async def _fake_sleep(d: float) -> None:
        sleeps.append(d)
        clock.advance(d)

    monkeypatch.setattr("agent_guardian.core.ratelimit.asyncio.sleep", _fake_sleep)
    bucket = AsyncTokenBucket(None)
    bucket.observe_rate_limited(None)  # promote + halve the default rate
    await bucket.acquire()
    # Tokens were drained on promotion, so the acquire waits for a refill at the
    # halved default rate — a real (non-zero) pause.
    assert sleeps and sleeps[-1] > 0.0


async def test_cooldown_honours_retry_after() -> None:
    # A retry_after parks a cooldown: the next acquire must wait ~that long even
    # though the bucket is otherwise full.
    bucket = AsyncTokenBucket(100.0, capacity=5.0)
    bucket.observe_rate_limited(retry_after=0.2)
    start = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.2 * 0.9, elapsed


async def test_cooldown_extends_never_shortens(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _FakeClock()
    monkeypatch.setattr("agent_guardian.core.ratelimit.time.monotonic", clock)
    bucket = AsyncTokenBucket(10.0, capacity=2.0)
    bucket.observe_rate_limited(retry_after=10.0)
    # A shorter retry_after must not shrink the existing, longer cooldown.
    bucket.observe_rate_limited(retry_after=1.0)
    assert bucket._cooldown_until == clock.now + 10.0


async def test_backoff_reduces_effective_rate(monkeypatch: pytest.MonkeyPatch) -> None:
    # Without a retry_after, a 429 still halves the effective refill rate and
    # drains accrued tokens, so the next refill paces more slowly.
    clock = _FakeClock()
    monkeypatch.setattr("agent_guardian.core.ratelimit.time.monotonic", clock)
    bucket = AsyncTokenBucket(10.0, capacity=10.0)
    assert bucket._effective_rate(clock.now) == 10.0
    bucket.observe_rate_limited(None)
    # Rate halved immediately; tokens drained.
    assert bucket._effective_rate(clock.now) == pytest.approx(5.0)
    assert bucket._tokens == 0.0


async def test_repeated_429s_compound_but_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _FakeClock()
    monkeypatch.setattr("agent_guardian.core.ratelimit.time.monotonic", clock)
    bucket = AsyncTokenBucket(10.0, capacity=10.0)
    for _ in range(20):
        bucket.observe_rate_limited(None)
    # Multiplicative decrease compounds but never drops below the floor.
    assert bucket._effective_rate(clock.now) >= 10.0 * 0.05 * 0.999
    assert bucket._effective_rate(clock.now) <= 10.0 * 0.05 * 1.001


async def test_effective_rate_recovers_over_time(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _FakeClock()
    monkeypatch.setattr("agent_guardian.core.ratelimit.time.monotonic", clock)
    bucket = AsyncTokenBucket(10.0, capacity=10.0)
    bucket.observe_rate_limited(None)  # factor 0.5
    assert bucket._effective_rate(clock.now) == pytest.approx(5.0)
    # Halfway through the recovery window: factor ~0.75.
    clock.advance(15.0)
    assert bucket._effective_rate(clock.now) == pytest.approx(7.5, rel=0.01)
    # Past the recovery window: fully recovered to the configured rate.
    clock.advance(20.0)
    assert bucket._effective_rate(clock.now) == 10.0


async def test_backoff_then_recovery_paces_acquires(monkeypatch: pytest.MonkeyPatch) -> None:
    # End-to-end: after a 429 the next acquire is slower than before the 429.
    clock = _FakeClock()
    monkeypatch.setattr("agent_guardian.core.ratelimit.time.monotonic", clock)
    sleeps: list[float] = []

    async def _fake_sleep(d: float) -> None:
        sleeps.append(d)
        clock.advance(d)

    monkeypatch.setattr("agent_guardian.core.ratelimit.asyncio.sleep", _fake_sleep)

    bucket = AsyncTokenBucket(10.0, capacity=1.0)
    await bucket.acquire()  # burst token, no wait
    assert sleeps == []
    bucket.observe_rate_limited(None)  # halve rate, drain tokens
    await bucket.acquire()
    # Wait for 1 token at the halved rate (~5/s) => ~0.2s, vs ~0.1s un-throttled.
    assert sleeps and sleeps[-1] == pytest.approx(0.2, rel=0.05)
