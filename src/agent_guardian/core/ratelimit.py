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
* **Adaptive back-off.** A target that answers ``429`` is telling us we are
  pacing too fast. :meth:`observe_rate_limited` reacts in two ways: it honours a
  server-supplied ``retry_after`` by parking a *cooldown* (no token is granted
  until it elapses) and it multiplicatively reduces the *effective* refill rate
  (AIMD-style) so subsequent calls keep some slack. The reduction decays back to
  the configured rate over a recovery window, so a transient burst of 429s
  throttles the scan briefly without permanently crippling it. The configured
  ``rate_per_sec`` is never mutated — only the effective rate the bucket paces
  at — so the bucket's public contract is unchanged.
"""

from __future__ import annotations

import asyncio
import time

__all__ = ["AsyncTokenBucket"]

# Multiplicative-decrease factor applied to the effective rate on each observed
# 429 (halve the throughput), and the floor it may not drop below (so the bucket
# never fully stalls on the rate axis — a parked cooldown handles hard stops).
_BACKOFF_FACTOR = 0.5
_MIN_RATE_FACTOR = 0.05
# How long (seconds) the effective rate takes to recover linearly back to the
# configured rate after the last observed 429.
_RECOVERY_SECONDS = 30.0


class AsyncTokenBucket:
    """A concurrency-safe asyncio token bucket.

    ``rate_per_sec`` tokens accrue per second up to ``capacity`` (default: a
    one-second burst, i.e. ``rate_per_sec``). When ``rate_per_sec`` is ``None``
    or non-positive the bucket is *disabled* and :meth:`acquire` is a no-op.

    The bucket also supports *adaptive* back-off via
    :meth:`observe_rate_limited`: an observed ``429`` parks a cooldown (honouring
    the server's ``retry_after``) and temporarily slows the effective refill
    rate, which recovers over :data:`_RECOVERY_SECONDS`.
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
        # Adaptive back-off state. ``_rate_factor`` scales the effective rate
        # (1.0 == configured rate); it is reduced on a 429 and recovers linearly.
        # ``_cooldown_until`` is a monotonic deadline before which no token is
        # granted (honours a server ``retry_after``). ``_factor_set_at`` marks
        # when the current reduced factor was applied so recovery can interpolate.
        self._rate_factor: float = 1.0
        self._factor_set_at: float = self._updated
        self._cooldown_until: float = 0.0

    @property
    def rate_per_sec(self) -> float:
        """The configured refill rate (``0.0`` when the bucket is disabled)."""
        return self._rate

    @property
    def capacity(self) -> float:
        """The maximum number of tokens the bucket can hold."""
        return self._capacity

    def _effective_rate(self, now: float) -> float:
        """The current refill rate after adaptive recovery toward the configured rate.

        The reduced ``_rate_factor`` decays linearly back to ``1.0`` over
        :data:`_RECOVERY_SECONDS` from the moment it was last set, so a one-off
        429 only briefly slows the scan.
        """
        if self._rate_factor >= 1.0:
            return self._rate
        elapsed = now - self._factor_set_at
        if elapsed >= _RECOVERY_SECONDS:
            factor = 1.0
        else:
            progress = elapsed / _RECOVERY_SECONDS
            factor = self._rate_factor + (1.0 - self._rate_factor) * progress
        return self._rate * factor

    def _refill_locked(self) -> None:
        """Accrue tokens for the elapsed monotonic interval (caller holds lock)."""
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0.0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._effective_rate(now))
            self._updated = now

    async def acquire(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them.

        No-op when the bucket is disabled. Cancellation-safe: if the awaiting
        coroutine is cancelled while waiting it has consumed nothing. When an
        adaptive cooldown is parked (see :meth:`observe_rate_limited`) no token
        is granted until the cooldown deadline passes, regardless of how many
        tokens have accrued.
        """
        if not self._enabled or tokens <= 0.0:
            return
        # Never wait forever for an unsatisfiable request: cap the demand at the
        # bucket's capacity so a caller asking for more than a full bucket still
        # makes progress instead of deadlocking.
        demand = min(tokens, self._capacity)
        while True:
            async with self._lock:
                now = time.monotonic()
                # Honour a parked cooldown first: no token is granted until it
                # elapses, even if the bucket is otherwise full.
                if now < self._cooldown_until:
                    wait = self._cooldown_until - now
                else:
                    self._refill_locked()
                    if self._tokens >= demand:
                        self._tokens -= demand
                        return
                    deficit = demand - self._tokens
                    # Pace against the *effective* rate so an adaptive slowdown
                    # widens the inter-request gap.
                    wait = deficit / self._effective_rate(now)
            # Sleep outside the lock so other awaiters can refill/observe, and so
            # a cancellation here never strands a deduction (we have taken none).
            await asyncio.sleep(wait)

    def observe_rate_limited(self, retry_after: float | None = None) -> None:
        """React to an observed ``429`` by backing off subsequent acquires.

        Two effects, both no-ops on a disabled bucket:

        * **Cooldown.** When ``retry_after`` (seconds) is supplied and positive,
          a cooldown is parked so the next :meth:`acquire` waits at least that
          long — honouring the server's explicit hint. Successive 429s extend
          (never shorten) the cooldown.
        * **Rate reduction.** The effective refill rate is multiplicatively
          reduced (by :data:`_BACKOFF_FACTOR`, floored at :data:`_MIN_RATE_FACTOR`)
          and the accrued tokens are drained, so even without a ``retry_after``
          the bucket re-paces more conservatively. The reduction recovers
          linearly back to the configured rate over :data:`_RECOVERY_SECONDS`.

        Synchronous + lock-free on purpose: it only stamps adaptive state read
        under the lock by :meth:`acquire`, so a caller can record a 429 from any
        context (including a transport error handler) without awaiting.
        """
        if not self._enabled:
            return
        now = time.monotonic()
        # Multiplicative decrease, floored so the rate axis never fully stalls.
        self._rate_factor = max(_MIN_RATE_FACTOR, self._rate_factor * _BACKOFF_FACTOR)
        self._factor_set_at = now
        # Drain accrued tokens so the slowdown bites immediately rather than
        # being masked by a full bucket.
        self._tokens = 0.0
        self._updated = now
        if retry_after is not None and retry_after > 0.0:
            self._cooldown_until = max(self._cooldown_until, now + float(retry_after))
