"""Tests for the M2 USD budget ledger (Pattern 7)."""

from __future__ import annotations

import asyncio
import json
import random
from pathlib import Path

import pytest

from agent_guardian.core.budget import (
    BudgetEnvelope,
    BudgetExhausted,
    BudgetLedger,
    tokens_to_usd,
)
from agent_guardian.llm.base import BaseLLM, LLMMessage, LLMRequest, LLMResponse
from agent_guardian.llm.budget_admission import BudgetAdmissionLLM, with_budget_admission
from agent_guardian.llm.stub import StubLLM
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM


def _envelope(
    usd: float = 1.0, tokens: int = 1_000_000, wall: float = 600.0, **shares: float
) -> BudgetEnvelope:
    return BudgetEnvelope(
        usd_cap=usd, token_cap=tokens, wallclock_cap_s=wall, per_agent_share=dict(shares)
    )


def test_reserve_then_commit_reduces_remaining() -> None:
    led = BudgetLedger(_envelope(usd=1.0))
    usd_before, _ = led.remaining("a")
    r = led.reserve("a", tokens=1000, est_usd=0.20)
    # Reservation counts against remaining immediately.
    usd_after_reserve, _ = led.remaining("a")
    assert usd_after_reserve == pytest.approx(usd_before - 0.20)
    led.commit(r, actual_usd=0.15)
    assert led.spent_usd == pytest.approx(0.15)


def test_reserve_over_envelope_cap_raises() -> None:
    led = BudgetLedger(_envelope(usd=0.10))
    with pytest.raises(BudgetExhausted):
        led.reserve("a", tokens=10, est_usd=0.50)


def test_reserve_over_agent_share_raises() -> None:
    # Agent "a" may use only 30% of the $1.00 cap = $0.30.
    led = BudgetLedger(_envelope(usd=1.0, a=0.30))
    led.reserve("a", tokens=10, est_usd=0.25)
    with pytest.raises(BudgetExhausted):
        led.reserve("a", tokens=10, est_usd=0.10)  # would push agent to 0.35 > 0.30


def test_token_cap_enforced() -> None:
    led = BudgetLedger(_envelope(usd=100.0, tokens=500))
    with pytest.raises(BudgetExhausted):
        led.reserve("a", tokens=600, est_usd=0.01)


def test_usage_fraction_and_exhaustion() -> None:
    led = BudgetLedger(_envelope(usd=1.0))
    r = led.reserve("a", tokens=10, est_usd=0.90)
    assert led.usage_fraction() == pytest.approx(0.90)
    led.commit(r, actual_usd=0.90)
    assert led.usage_fraction() == pytest.approx(0.90)
    led.reserve("a", tokens=10, est_usd=0.10)
    assert led.is_exhausted() is True


def test_commit_unknown_receipt_raises() -> None:
    led = BudgetLedger(_envelope())
    r = led.reserve("a", tokens=10, est_usd=0.01)
    led.commit(r, actual_usd=0.01)
    with pytest.raises(ValueError):
        led.commit(r, actual_usd=0.01)  # already committed


def test_tokens_to_usd() -> None:
    assert tokens_to_usd("stub", 1000, 1000) == 0.0
    # gpt-4o-mini: 0.15 in / 0.60 out per 1M.
    usd = tokens_to_usd("gpt-4o-mini", 1_000_000, 1_000_000)
    assert usd == pytest.approx(0.75)


def test_jsonl_audit_trail(tmp_path: Path) -> None:
    p = tmp_path / "ledger.jsonl"
    led = BudgetLedger(_envelope(), jsonl_path=p)
    r = led.reserve("a", tokens=10, est_usd=0.01)
    led.commit(r, actual_usd=0.01)
    lines = p.read_text().splitlines()
    kinds = [json.loads(line)["kind"] for line in lines]
    assert kinds == ["reserve", "commit"]


def test_property_spend_never_exceeds_cap() -> None:
    """Across many random reserve/commit cycles, committed spend stays <= cap."""
    rng = random.Random(1234)
    for _ in range(200):
        cap = rng.uniform(0.5, 5.0)
        led = BudgetLedger(_envelope(usd=cap, tokens=10_000_000))
        for _ in range(100):
            amt = rng.uniform(0.0, 0.5)
            try:
                r = led.reserve("a", tokens=rng.randint(0, 1000), est_usd=amt)
            except BudgetExhausted:
                continue
            # Actual cost can drift up to 20% above the estimate; the ledger
            # must still never let committed spend exceed the cap because the
            # reservation gate is on the estimate. We model honest estimates.
            led.commit(r, actual_usd=amt)
        assert led.spent_usd <= cap + 1e-9


class _FailingLLM(BaseLLM):
    provider = "gemini"

    def __init__(self, *, wait: bool = False) -> None:
        super().__init__(owns_client=False)
        self.started = asyncio.Event()
        self._wait = wait

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.started.set()
        if self._wait:
            await asyncio.Event().wait()
        raise RuntimeError("provider failed")


def _request() -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="user", content="hello")],
        model="gemini-2.5-flash",
        max_tokens=32,
    )


@pytest.mark.asyncio
async def test_admission_receipt_is_conservatively_settled_on_exception() -> None:
    ledger = BudgetLedger(_envelope(usd=1.0))
    llm = BudgetAdmissionLLM(_FailingLLM(), ledger=ledger, agent_id="evaluator")

    with pytest.raises(RuntimeError, match="provider failed"):
        await llm.complete(_request())

    assert [entry.kind for entry in ledger.entries()] == ["reserve", "commit"]
    assert ledger.committed_plus_reserved_usd == pytest.approx(ledger.spent_usd)


@pytest.mark.asyncio
async def test_admission_receipt_is_conservatively_settled_on_cancellation() -> None:
    ledger = BudgetLedger(_envelope(usd=1.0))
    inner = _FailingLLM(wait=True)
    llm = BudgetAdmissionLLM(inner, ledger=ledger, agent_id="attacker")
    task = asyncio.create_task(llm.complete(_request()))
    await inner.started.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert [entry.kind for entry in ledger.entries()] == ["reserve", "commit"]
    assert ledger.committed_plus_reserved_usd == pytest.approx(ledger.spent_usd)


@pytest.mark.asyncio
async def test_admission_does_not_double_count_pretracked_usage() -> None:
    counter = UsageCounter()
    tracked = UsageTrackingLLM(StubLLM(default="ok"), counter=counter)
    llm = with_budget_admission(
        tracked,
        ledger=BudgetLedger(_envelope(usd=1.0)),
        agent_id="commander",
    )

    await llm.complete(_request())

    assert counter.calls == 1
