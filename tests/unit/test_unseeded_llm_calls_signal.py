"""Issue #231 point 5 — ``coverage.unseeded_llm_calls`` self-diagnosing signal.

When a scan is launched with ``--seed`` but some path forgets to thread the
seed onto its :class:`LLMRequest`, that call silently loses reproducibility.
The ``unseeded_llm_calls`` counter makes that visible: it counts LLM calls
dispatched with ``seed=None`` at the transport (:class:`UsageTrackingLLM`)
layer, and the report surfaces it under ``coverage`` (defaulting to 0).

These tests pin three contracts:

* the dispatch layer increments the counter on a ``seed=None`` call and leaves
  it untouched on a seeded call;
* the counter survives a provider that raises (signal is recorded pre-call);
* the ``coverage`` block always exposes the field (default 0) and reflects an
  injected count.
"""

from __future__ import annotations

import pytest

from agent_guardian.core.coverage import compute_coverage_from_memory
from agent_guardian.llm.base import LLMMessage, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM


def _make_request(seed: int | None) -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="user", content="x")],
        model="stub:model",
        seed=seed,
    )


def _make_response() -> LLMResponse:
    return LLMResponse(
        text="ok",
        model="stub:model",
        provider="stub",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )


class _FakeInner:
    provider = "stub"

    def __init__(self, *, raises: bool = False) -> None:
        self._raises = raises

    async def complete(self, request: LLMRequest) -> LLMResponse:
        if self._raises:
            raise RuntimeError("boom")
        return _make_response()


# ---------------------------------------------------------------------------
# UsageCounter / UsageTrackingLLM dispatch-layer counting.
# ---------------------------------------------------------------------------


def test_usage_counter_snapshot_exposes_field_default_zero() -> None:
    counter = UsageCounter()
    snap = counter.snapshot()
    assert snap["unseeded_llm_calls"] == 0


@pytest.mark.asyncio
async def test_unseeded_call_increments_counter() -> None:
    counter = UsageCounter()
    wrapped = UsageTrackingLLM(_FakeInner(), counter=counter)

    await wrapped.complete(_make_request(seed=None))

    assert counter.unseeded_llm_calls == 1
    assert counter.calls == 1


@pytest.mark.asyncio
async def test_seeded_call_does_not_increment_counter() -> None:
    counter = UsageCounter()
    wrapped = UsageTrackingLLM(_FakeInner(), counter=counter)

    await wrapped.complete(_make_request(seed=7))

    assert counter.unseeded_llm_calls == 0
    assert counter.calls == 1


@pytest.mark.asyncio
async def test_unseeded_signal_recorded_even_when_provider_raises() -> None:
    counter = UsageCounter()
    wrapped = UsageTrackingLLM(_FakeInner(raises=True), counter=counter)

    with pytest.raises(RuntimeError):
        await wrapped.complete(_make_request(seed=None))

    # The seed-miss signal is recorded before dispatch, so a provider failure
    # does not hide it. The token call count stays 0 (no response observed).
    assert counter.unseeded_llm_calls == 1
    assert counter.calls == 0


def test_counter_does_not_leak_across_scans() -> None:
    """Each scan builds a fresh counter; a new instance starts at zero."""
    first = UsageCounter()
    first.unseeded_llm_calls = 5
    second = UsageCounter()
    assert second.unseeded_llm_calls == 0


def test_merge_folds_unseeded_counts() -> None:
    a = UsageCounter(unseeded_llm_calls=2)
    b = UsageCounter(unseeded_llm_calls=3)
    a.merge(b)
    assert a.unseeded_llm_calls == 5


# ---------------------------------------------------------------------------
# Coverage block surfacing.
# ---------------------------------------------------------------------------


def test_coverage_block_defaults_unseeded_to_zero(tmp_path) -> None:
    # No memory file -> empty coverage shape, field present and 0.
    cov = compute_coverage_from_memory(memory_path=tmp_path / "missing.jsonl")
    assert cov["unseeded_llm_calls"] == 0


def test_coverage_block_reflects_injected_count(tmp_path) -> None:
    cov = compute_coverage_from_memory(
        memory_path=tmp_path / "missing.jsonl",
        unseeded_llm_calls=4,
    )
    assert cov["unseeded_llm_calls"] == 4
