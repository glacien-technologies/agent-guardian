"""Gemini circuit-breaker / pre-flight (rc38 P0-#5 / #263).

Two invariants:

1. The token bucket gates request RATE (calls per N seconds) — the per-
   instance ``asyncio.Semaphore`` only gates concurrency. Without the
   bucket, a burst of N quick scans against a free-tier key triggers a
   429 cascade that burns the retry budget in <10s.
2. ``GeminiClient.preflight()`` sends one cheap completion and re-raises
   :class:`LLMRateLimitError` only — so the CLI can fail-fast with a
   distinct exit code when the key is already quota-exhausted, without
   committing the recon + seat-prep budgets to a hopeless scan.
"""

from __future__ import annotations

import time

import pytest
import respx
from httpx import Response

from agent_guardian.llm.base import LLMMessage, LLMRequest
from agent_guardian.llm.errors import LLMRateLimitError
from agent_guardian.llm.gemini import GeminiClient, _AsyncTokenBucket

_HAPPY_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
)


def _happy(text: str = "ok") -> dict[str, object]:
    return {
        "candidates": [
            {"content": {"parts": [{"text": text}], "role": "model"}, "finishReason": "STOP"}
        ],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
        "modelVersion": "gemini-2.5-flash",
    }


# ---------------------------------------------------------------------------
# _AsyncTokenBucket unit invariants
# ---------------------------------------------------------------------------


async def test_token_bucket_admits_initial_capacity_without_wait() -> None:
    """A fresh bucket starts at capacity; ``capacity`` calls in a row must
    return immediately."""
    bucket = _AsyncTokenBucket(capacity=3, refill_seconds=60.0)
    t0 = time.monotonic()
    for _ in range(3):
        await bucket.acquire()
    elapsed = time.monotonic() - t0
    assert elapsed < 0.1, f"initial {3} acquires should be near-instant; got {elapsed:.2f}s"


async def test_token_bucket_throttles_after_exhausting_capacity() -> None:
    """The (capacity + 1)-th call must wait until a token refills.

    With capacity=2, refill_seconds=0.4, one token refills every 0.2s, so
    the third acquire should wait ~0.2s (within tolerance)."""
    bucket = _AsyncTokenBucket(capacity=2, refill_seconds=0.4)
    await bucket.acquire()
    await bucket.acquire()
    t0 = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - t0
    assert 0.05 <= elapsed <= 0.5, f"third acquire should wait ~0.2s for refill; got {elapsed:.2f}s"


def test_token_bucket_rejects_invalid_capacity() -> None:
    with pytest.raises(ValueError):
        _AsyncTokenBucket(capacity=0, refill_seconds=60.0)
    with pytest.raises(ValueError):
        _AsyncTokenBucket(capacity=-1, refill_seconds=60.0)


def test_token_bucket_rejects_invalid_refill() -> None:
    with pytest.raises(ValueError):
        _AsyncTokenBucket(capacity=1, refill_seconds=0)
    with pytest.raises(ValueError):
        _AsyncTokenBucket(capacity=1, refill_seconds=-5.0)


# ---------------------------------------------------------------------------
# Pre-flight invariant
# ---------------------------------------------------------------------------


@respx.mock
async def test_preflight_fails_fast_on_429() -> None:
    """A 429 on the cheap probe must surface as :class:`LLMRateLimitError`
    so the CLI can exit before committing the scan budget."""
    body = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "message": "Quota exceeded",
            "details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "30s"}],
        }
    }
    route = respx.post(_HAPPY_URL).mock(return_value=Response(429, json=body))
    llm = GeminiClient(api_key="k", rate_limiter=None)
    with pytest.raises(LLMRateLimitError):
        await llm.preflight()
    # Exactly one round-trip (we don't retry — the whole point is fail-fast).
    assert route.call_count == 1
    await llm.aclose()


@respx.mock
async def test_preflight_returns_none_on_happy_path() -> None:
    """A 200 on the cheap probe completes silently — the CLI proceeds to
    the real scan."""
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy()))
    llm = GeminiClient(api_key="k", rate_limiter=None)
    out = await llm.preflight()
    assert out is None
    await llm.aclose()


# ---------------------------------------------------------------------------
# Rate-limiter wiring on _send
# ---------------------------------------------------------------------------


@respx.mock
async def test_send_acquires_token_before_request() -> None:
    """The client must call its bucket's ``acquire`` exactly once per
    completion before the HTTP call goes out."""

    class _RecordingBucket(_AsyncTokenBucket):
        def __init__(self) -> None:
            super().__init__(capacity=100, refill_seconds=60.0)
            self.calls = 0

        async def acquire(self) -> None:
            self.calls += 1
            await super().acquire()

    bucket = _RecordingBucket()
    respx.post(_HAPPY_URL).mock(return_value=Response(200, json=_happy("hello")))
    llm = GeminiClient(api_key="k", rate_limiter=bucket)
    req = LLMRequest(messages=[LLMMessage(role="user", content="hi")], model="gemini-2.5-flash")
    await llm._send(req)
    assert bucket.calls == 1
    await llm.aclose()


async def test_rate_limiter_none_disables_gate() -> None:
    """Passing ``rate_limiter=None`` is the explicit opt-OUT — the client
    must record ``self._rate_limiter is None`` and skip the acquire call.

    This is a wiring assertion: the heavier "actually doesn't throttle"
    invariant is covered by the recording-bucket test above; here we just
    pin the opt-out contract."""
    llm = GeminiClient(api_key="k", rate_limiter=None)
    assert llm._rate_limiter is None
    await llm.aclose()
