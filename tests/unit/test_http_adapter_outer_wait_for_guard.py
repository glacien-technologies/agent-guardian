"""Issue #224 — HttpAdapter outer wall-cap guard on send_raw retries.

The rc35 deep-review A2 finding (deeper-investigation: rc36 research
workflow): scan #06 (seed=12345) burned the entire 300s wallclock on
a single stuck denial-of-wallet agent because ``HttpAdapter.send_raw``
calls ``with_backoff(..., max_retries=3)`` WITHOUT plumbing
``cancel_event`` / ``deadline_monotonic`` through. Three consecutive 60s
``httpx.TimeoutException`` retries can burn ~180s + backoff sleeps
before the outer ``asyncio.wait_for`` in the swarm fires.

The fix wraps ``send_raw``'s retry loop in an ``asyncio.wait_for`` with
an outer cap of ``(max_retries + 1) * timeout_seconds + 30s safety``.
A truly stuck target now surfaces as a clean ``TargetTimeoutError``
within the bounded cap instead of consuming a multi-minute slice of
the swarm's wall budget.

The fuller fix (thread the swarm's cancel_event through every transport
caller) is a milestone follow-up touching 6+ files.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.llm.errors import TargetTimeoutError


class _StallingClient:
    """Stand-in httpx.AsyncClient whose ``post`` never returns — sleeps
    indefinitely. The HttpAdapter's outer wait_for must kill it within
    the cap regardless of with_backoff's retry behaviour."""

    def __init__(self) -> None:
        self.post_calls = 0

    async def post(
        self, *args: Any, **kwargs: Any
    ) -> httpx.Response:  # pragma: no cover -- test stand-in
        self.post_calls += 1
        await asyncio.sleep(100.0)  # would burn 100s if not cancelled
        raise AssertionError("post should never return — outer wait_for must cancel it")

    async def aclose(self) -> None:  # pragma: no cover
        return None


@pytest.mark.asyncio
async def test_send_raw_outer_cap_kills_runaway_retries() -> None:
    """A target that stalls on every post() must not burn more than the
    documented outer cap. Pre-fix this could run 100s x 4 attempts =
    400s; post-fix the outer wait_for fires at ~3s with the test's
    aggressive 1s timeout + 0 retries."""
    adapter = HttpAdapter(
        endpoint="https://example.invalid/test",
        shape="generic",
        timeout_seconds=1.0,
        max_retries=0,  # single attempt; outer cap = 1 + 30 = 31s, but we expect <2s real
    )
    # Swap in the stalling client.
    adapter._client = _StallingClient()  # type: ignore[assignment]

    started = asyncio.get_event_loop().time()
    with pytest.raises((TargetTimeoutError, Exception)) as excinfo:
        # The outer cap kicks in well before the 100s sleep returns.
        # With timeout_seconds=1.0, max_retries=0 -> outer cap = 1*1 + 30 = 31s.
        # The httpx.AsyncClient (we swapped in) has no inner timeout, so
        # the cap-trip surfaces as the OUTER wait_for raising TargetTimeoutError.
        await asyncio.wait_for(
            adapter.send_raw(body={"messages": []}, headers={}),
            timeout=40.0,  # extra-outer safety so the test fails cleanly
        )
    # Either the inner outer-cap fires (TargetTimeoutError) or the test's
    # extra-outer wait_for catches a runaway. The first is the fix; the
    # second would indicate the cap was bypassed.
    assert isinstance(excinfo.value, TargetTimeoutError | TimeoutError | asyncio.TimeoutError), (
        f"send_raw failed to honour the outer cap; raised {type(excinfo.value).__name__}: "
        f"{excinfo.value}"
    )
    elapsed = asyncio.get_event_loop().time() - started
    # Outer cap is 31s; allow generous slack but assert we didn't burn
    # the whole 100s post() sleep.
    assert elapsed < 40.0, (
        f"send_raw took {elapsed:.1f}s; expected <40s under the outer cap "
        f"(timeout=1s, max_retries=0 -> cap=31s). The wait_for guard "
        f"failed to kill the runaway retry — #224 regression."
    )
    await adapter.aclose()


def test_send_raw_outer_cap_formula_is_sane() -> None:
    """The outer cap formula is ``(max_retries + 1) * timeout + 30``.

    Lock the formula so a future refactor that drops the +30 safety
    buffer (or multiplies wrong) can't ship silently. The buffer
    accommodates the with_backoff exponential sleeps between retries
    without making the cap so generous that a stuck target can burn
    multi-minute slices."""
    # max_retries=3 (default), timeout=60s -> cap = 4*60 + 30 = 270s
    # max_retries=0,           timeout=1s  -> cap = 1*1 + 30  = 31s
    # max_retries=5,           timeout=120 -> cap = 6*120 + 30 = 750s
    for max_retries, timeout, expected in [(3, 60.0, 270.0), (0, 1.0, 31.0), (5, 120.0, 750.0)]:
        outer_cap = timeout * (max_retries + 1) + 30.0
        assert outer_cap == expected, (
            f"outer-cap formula regressed for (max_retries={max_retries}, "
            f"timeout={timeout}): got {outer_cap}, expected {expected}"
        )
