"""Tests for the retry helper."""

from __future__ import annotations

import random

import pytest

from agent_guardian.llm.errors import (
    LLMPermanentError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import compute_delay, with_backoff


def test_compute_delay_base_case() -> None:
    rng = random.Random(0)
    d = compute_delay(0, base_seconds=1.0, factor=2.0, jitter_pct=0.0, rng=rng)
    assert d == pytest.approx(1.0)


def test_compute_delay_exponential_growth() -> None:
    rng = random.Random(0)
    d0 = compute_delay(0, base_seconds=1.0, factor=2.0, jitter_pct=0.0, rng=rng)
    d1 = compute_delay(1, base_seconds=1.0, factor=2.0, jitter_pct=0.0, rng=rng)
    d2 = compute_delay(2, base_seconds=1.0, factor=2.0, jitter_pct=0.0, rng=rng)
    assert d0 == pytest.approx(1.0)
    assert d1 == pytest.approx(2.0)
    assert d2 == pytest.approx(4.0)


def test_compute_delay_clamps_to_max() -> None:
    rng = random.Random(0)
    d = compute_delay(20, base_seconds=1.0, factor=2.0, jitter_pct=0.0, max_seconds=5.0, rng=rng)
    assert d == pytest.approx(5.0)


def test_compute_delay_jitter_bounds() -> None:
    rng = random.Random(0)
    for _ in range(50):
        d = compute_delay(2, base_seconds=1.0, factor=2.0, jitter_pct=0.25, rng=rng)
        # 4.0 * (1 ± 0.25) = [3.0, 5.0]
        assert 3.0 <= d <= 5.0


def test_compute_delay_validates_inputs() -> None:
    with pytest.raises(ValueError):
        compute_delay(-1)
    with pytest.raises(ValueError):
        compute_delay(0, base_seconds=-1)
    with pytest.raises(ValueError):
        compute_delay(0, factor=0.5)
    with pytest.raises(ValueError):
        compute_delay(0, jitter_pct=1.0)
    with pytest.raises(ValueError):
        compute_delay(0, jitter_pct=-0.1)


def test_compute_delay_rng_is_deterministic() -> None:
    a = compute_delay(3, jitter_pct=0.25, rng=random.Random(42))
    b = compute_delay(3, jitter_pct=0.25, rng=random.Random(42))
    assert a == b


async def test_with_backoff_succeeds_first_try() -> None:
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        return "ok"

    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    result = await with_backoff(coro, sleep=fake_sleep, rng=random.Random(0))
    assert result == "ok"
    assert calls == 1
    assert sleeps == []


async def test_with_backoff_retries_then_succeeds() -> None:
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise LLMTransientError("blip")
        return "ok"

    sleeps: list[float] = []

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
    assert calls == 3
    # Two retries → two sleeps of ~1.0, ~2.0
    assert len(sleeps) == 2
    assert sleeps[0] == pytest.approx(1.0)
    assert sleeps[1] == pytest.approx(2.0)


async def test_with_backoff_honours_retry_after() -> None:
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise LLMRateLimitError("rate", retry_after=7.5)
        return "ok"

    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    result = await with_backoff(coro, sleep=fake_sleep, rng=random.Random(0))
    assert result == "ok"
    assert sleeps == [7.5]


async def test_with_backoff_gives_up_after_max_retries() -> None:
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        raise LLMTransientError("always fails")

    async def fake_sleep(s: float) -> None:
        return None

    with pytest.raises(LLMTransientError):
        await with_backoff(
            coro,
            max_retries=2,
            sleep=fake_sleep,
            rng=random.Random(0),
        )
    assert calls == 3  # initial + 2 retries


async def test_with_backoff_does_not_retry_unlisted_exception() -> None:
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        raise LLMPermanentError("nope")

    async def fake_sleep(s: float) -> None:
        return None

    with pytest.raises(LLMPermanentError):
        await with_backoff(coro, sleep=fake_sleep, rng=random.Random(0))
    assert calls == 1


async def test_with_backoff_retries_timeout() -> None:
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        if calls < 2:
            raise LLMTimeoutError("slow")
        return "ok"

    async def fake_sleep(s: float) -> None:
        return None

    result = await with_backoff(coro, sleep=fake_sleep, rng=random.Random(0))
    assert result == "ok"
    assert calls == 2


async def test_with_backoff_negative_retry_after_falls_back_to_computed() -> None:
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise LLMRateLimitError("rate", retry_after=-3.0)
        return "ok"

    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    await with_backoff(
        coro,
        base_seconds=1.0,
        factor=2.0,
        jitter_pct=0.0,
        sleep=fake_sleep,
        rng=random.Random(0),
    )
    # Negative retry_after is treated as "no header" — falls back to computed.
    assert sleeps == [pytest.approx(1.0)]
