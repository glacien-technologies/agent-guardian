"""Async token-bucket rate limiter (Stage 1B).

A single :class:`AsyncTokenBucket` is the request-pacing primitive the RoE
controller leans on: every target call awaits :meth:`acquire` before it is
allowed to leave the process. The bucket is the *only* place RoE rate limiting
lives, so it must be correct under heavy concurrency (many coroutines awaiting
the same bucket at once) and under cancellation (an awaiter that is cancelled
must not strand the tokens it was about to consume).

Design notes:

* **Monotonic-clock refill.** Tokens accrue at ``rate_per_sec`` based on
  :func:`time.monotonic` deltas, so a wall-clock jump can never grant a burst.
* **Lock-guarded accounting.** All mutation of the token count happens under an
  :class:`asyncio.Lock`, so concurrent awaiters serialise their bookkeeping and
  the bucket cannot over-grant.
* **Cancellation-safe sleeps.** An awaiter computes how long it must wait, then
  sleeps *outside* the lock. If it is cancelled mid-sleep it has consumed
  nothing (the deduction happens only once it actually has the tokens), so no
  capacity is lost.
* **No-op fast path.** A ``rate_per_sec`` of ``None`` or ``<= 0`` disables
  limiting entirely — :meth:`acquire` returns immediately without taking the
  lock — so an un-throttled contract pays no overhead.
"""

from __future__ import annotations

import asyncio
import time

__all__ = ["AsyncTokenBucket"]


class AsyncTokenBucket:
    """A concurrency-safe asyncio token bucket.

    ``rate_per_sec`` tokens accrue per second up to ``capacity`` (default: a
    one-second burst, i.e. ``rate_per_sec``). When ``rate_per_sec`` is ``None``
    or non-positive the bucket is *disabled* and :meth:`acquire` is a no-op.
    """

    def __init__(self, rate_per_sec: float | None, *, capacity: float | None = None) -> None:
        self._rate: float = float(rate_per_sec) if rate_per_sec is not None else 0.0
        self._enabled: bool = self._rate > 0.0
        if capacity is not None:
            self._capacity = float(capacity)
        elif self._enabled:
            self._capacity = self._rate
        else:
            self._capacity = 0.0
        # Start full so the first burst (up to capacity) is immediate.
        self._tokens: float = self._capacity
        self._updated: float = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def rate_per_sec(self) -> float:
        """The configured refill rate (``0.0`` when the bucket is disabled)."""
        return self._rate

    @property
    def capacity(self) -> float:
        """The maximum number of tokens the bucket can hold."""
        return self._capacity

    def _refill_locked(self) -> None:
        """Accrue tokens for the elapsed monotonic interval (caller holds lock)."""
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0.0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._updated = now

    async def acquire(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them.

        No-op when the bucket is disabled. Cancellation-safe: if the awaiting
        coroutine is cancelled while waiting it has consumed nothing.
        """
        if not self._enabled or tokens <= 0.0:
            return
        # Never wait forever for an unsatisfiable request: cap the demand at the
        # bucket's capacity so a caller asking for more than a full bucket still
        # makes progress instead of deadlocking.
        demand = min(tokens, self._capacity)
        while True:
            async with self._lock:
                self._refill_locked()
                if self._tokens >= demand:
                    self._tokens -= demand
                    return
                deficit = demand - self._tokens
                wait = deficit / self._rate
            # Sleep outside the lock so other awaiters can refill/observe, and so
            # a cancellation here never strands a deduction (we have taken none).
            await asyncio.sleep(wait)
