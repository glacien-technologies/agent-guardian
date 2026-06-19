"""Tests for the retry helper."""

from __future__ import annotations

import asyncio
import random

import pytest

from agent_guardian.llm.errors import (
    LLMPermanentError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.llm.retry import (
    AGENT_LOOP_MAX_RETRIES,
    AGENT_LOOP_MAX_SECONDS,
    compute_delay,
    with_backoff,
)


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


# ----------------------------------------------------------------- cancellation


def test_agent_loop_defaults_are_tighter_than_public_defaults() -> None:
    """Agent-loop ceiling MUST stay below the public 60s/6-retry default.

    A regression here would mean an EARLY_STOP could once again soak the
    wall-clock budget while an attacker LLM is locked in a 503 cycle.
    """
    assert AGENT_LOOP_MAX_RETRIES <= 3
    assert AGENT_LOOP_MAX_SECONDS <= 15.0


async def test_with_backoff_cancel_event_interrupts_mid_backoff() -> None:
    """Setting the cancel event mid-sleep re-raises the retryable error promptly."""
    cancel = asyncio.Event()
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        raise LLMTransientError("blip")

    async def fake_sleep(_s: float) -> None:
        # Simulate a long backoff that gets cancelled mid-wait. Yield once so
        # the cancel_event.wait() task gets a chance to register, then await
        # an event that never fires -- the wrapper's asyncio.wait will return
        # via the cancel path.
        cancel.set()
        await asyncio.sleep(0)

    with pytest.raises(LLMTransientError):
        await with_backoff(
            coro,
            max_retries=5,
            sleep=fake_sleep,
            rng=random.Random(0),
            cancel_event=cancel,
        )
    # We made the first attempt, hit retry, slept, the cancel fired during
    # sleep -> we re-raised the most recent exception. No second attempt.
    assert calls == 1


async def test_with_backoff_cancel_event_already_set_before_first_call() -> None:
    """Cancellation set before any attempt raises CancelledError immediately."""
    cancel = asyncio.Event()
    cancel.set()
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        return "never"

    async def fake_sleep(_s: float) -> None:
        return None

    with pytest.raises(asyncio.CancelledError):
        await with_backoff(
            coro,
            max_retries=3,
            sleep=fake_sleep,
            rng=random.Random(0),
            cancel_event=cancel,
        )
    assert calls == 0


async def test_with_backoff_cancel_event_unset_runs_normally() -> None:
    """A cancel_event that never fires must not affect the success path."""
    cancel = asyncio.Event()
    calls = 0

    async def coro() -> str:
        nonlocal calls
        calls += 1
        if calls < 2:
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
        cancel_event=cancel,
    )
    assert result == "ok"
    assert calls == 2
    assert len(sleeps) == 1


# --------------------------------------------------------------------------- #
# rc38 P0-#5 (#263) — scan-scoped retry tally
# --------------------------------------------------------------------------- #


async def test_retry_tally_counts_calls_and_exhaustions() -> None:
    """Within a scope, ``with_backoff`` counts every call and the subset whose
    retries were exhausted."""
    from agent_guardian.llm.retry import retry_tally_scope

    async def ok() -> str:
        return "ok"

    async def always_fail() -> str:
        raise LLMTransientError("boom")

    async def fake_sleep(_s: float) -> None:
        return None

    with retry_tally_scope() as tally:
        await with_backoff(ok, sleep=fake_sleep, rng=random.Random(0))
        await with_backoff(ok, sleep=fake_sleep, rng=random.Random(0))
        with pytest.raises(LLMTransientError):
            await with_backoff(always_fail, max_retries=1, sleep=fake_sleep, rng=random.Random(0))
    assert tally.total == 3
    assert tally.exhausted == 1
    assert tally.exhausted_ratio == pytest.approx(1 / 3)


async def test_retry_tally_does_not_leak_across_scopes() -> None:
    """A fresh scope starts at zero; the previous binding is restored on exit."""
    from agent_guardian.llm.retry import (
        current_retry_tally,
        retry_tally_scope,
    )

    async def ok() -> str:
        return "ok"

    assert current_retry_tally() is None
    with retry_tally_scope() as first:
        await with_backoff(ok)
        assert first.total == 1
    # Outside any scope the tally is None again (no leak).
    assert current_retry_tally() is None
    with retry_tally_scope() as second:
        assert second.total == 0
        await with_backoff(ok)
        assert second.total == 1


async def test_with_backoff_outside_scope_is_noop_for_tally() -> None:
    """``with_backoff`` outside a scope must not raise — counting is skipped."""
    from agent_guardian.llm.retry import current_retry_tally

    async def ok() -> str:
        return "ok"

    assert current_retry_tally() is None
    result = await with_backoff(ok)
    assert result == "ok"


def test_retry_tally_ratio_zero_when_empty() -> None:
    """An empty tally reports a 0.0 ratio (no div-by-zero)."""
    from agent_guardian.llm.retry import RetryTally

    assert RetryTally().exhausted_ratio == 0.0
