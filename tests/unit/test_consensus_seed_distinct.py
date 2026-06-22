"""Issue #231 point 3 — distinct, deterministic per-seat consensus seeds.

``AsiAgent._judge_with_consensus`` previously fired its ``n`` parallel judge
calls with the *same* :class:`LLMRequest` object, so every seat carried the
identical seed. Against a deterministic provider that collapses the ``n``
samples into one verdict (defeating the variance-reduction purpose of L2), and
under provider jitter the :func:`asyncio.gather` completion order made the
bucket tally order-dependent.

The fix gives seat ``i`` the seed ``base_seed + i`` by building a per-seat
:meth:`~pydantic.BaseModel.model_copy` of the request. When the scan was
launched without ``--seed`` (``request.seed is None``) every seat stays
unseeded — we never invent a seed the operator did not ask for.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agent_guardian.agents.base import AsiAgent
from agent_guardian.llm.base import LLMMessage, LLMRequest, LLMResponse, LLMUsage


def _make_request(seed: int | None) -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="user", content="rate this")],
        model="stub:judge",
        temperature=0.0,
        seed=seed,
    )


def _make_response() -> LLMResponse:
    """A parseable ``defended`` verdict so the tally has a clean majority."""
    return LLMResponse(
        text='{"verdict": "defended", "confidence": 1.0}',
        model="stub:judge",
        provider="stub",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )


# ---------------------------------------------------------------------------
# Static helper — the seed math in isolation.
# ---------------------------------------------------------------------------


def test_consensus_requests_offsets_seed_per_seat() -> None:
    req = _make_request(seed=42)
    out = AsiAgent._consensus_requests(req, 3)
    assert [r.seed for r in out] == [42, 43, 44]
    # Distinct objects (frozen model copies), original untouched.
    assert req.seed == 42
    assert len({id(r) for r in out}) == 3


def test_consensus_requests_none_seed_stays_none() -> None:
    req = _make_request(seed=None)
    out = AsiAgent._consensus_requests(req, 3)
    assert [r.seed for r in out] == [None, None, None]


# ---------------------------------------------------------------------------
# End-to-end — capture what _judge_with_consensus actually dispatches.
# ---------------------------------------------------------------------------


class _RecordingLLM:
    """Records every request handed to ``complete`` and returns a fixed reply."""

    def __init__(self) -> None:
        self.requests: list[LLMRequest] = []

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        return _make_response()


@pytest.mark.asyncio
async def test_judge_with_consensus_dispatches_distinct_seeds() -> None:
    llm = _RecordingLLM()
    # _judge_with_consensus only touches self.evaluator_llm and the static
    # _consensus_requests helper, so a minimal stand-in exercises the real path
    # without constructing a concrete agent subclass.
    fake_self: Any = SimpleNamespace(
        evaluator_llm=llm,
        _consensus_requests=AsiAgent._consensus_requests,
    )
    await AsiAgent._judge_with_consensus(fake_self, _make_request(seed=42), n=3)

    seeds = [r.seed for r in llm.requests]
    assert seeds == [42, 43, 44], (
        f"consensus seats dispatched seeds {seeds}; expected base_seed+i "
        f"[42, 43, 44] so the tally is independent of gather order (#231)"
    )


@pytest.mark.asyncio
async def test_judge_with_consensus_unseeded_dispatches_all_none() -> None:
    llm = _RecordingLLM()
    fake_self: Any = SimpleNamespace(
        evaluator_llm=llm,
        _consensus_requests=AsiAgent._consensus_requests,
    )
    await AsiAgent._judge_with_consensus(fake_self, _make_request(seed=None), n=3)

    seeds = [r.seed for r in llm.requests]
    assert seeds == [None, None, None], (
        f"unseeded scan dispatched seeds {seeds}; expected all None — a seed "
        f"must never be invented when the scan ran without --seed (#231)"
    )


# ---------------------------------------------------------------------------
# Failure-handling / tally — the consensus body we rewrote must stay resilient
# when individual seats flake (the whole point of voting across N seats).
# ---------------------------------------------------------------------------


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        model="stub:judge",
        provider="stub",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )


class _ScriptedLLM:
    """Returns/raises a scripted outcome per ``complete`` call.

    The first ``len(script)`` calls consume the script in dispatch order; once
    exhausted every further call returns a parseable ``defended`` reply. This
    lets a single fake drive both the N consensus seats and the single-call
    fallback in one test.
    """

    def __init__(self, script: list[Any] | None = None) -> None:
        self._script = list(script or [])
        self.calls = 0

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        if self._script:
            outcome = self._script.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            if isinstance(outcome, LLMResponse):
                return outcome
        return _make_response()


def _fake_agent(llm: Any) -> Any:
    return SimpleNamespace(
        evaluator_llm=llm,
        _consensus_requests=AsiAgent._consensus_requests,
    )


@pytest.mark.asyncio
async def test_consensus_single_call_when_n_le_1() -> None:
    """``n <= 1`` short-circuits to a single plain completion (no seed math)."""
    llm = _ScriptedLLM()
    out = await AsiAgent._judge_with_consensus(_fake_agent(llm), _make_request(seed=42), n=1)
    assert llm.calls == 1
    assert out.text == _make_response().text


@pytest.mark.asyncio
async def test_consensus_tolerates_one_failed_seat_and_still_tallies() -> None:
    """One seat raising is bucketed as a non-vote; the other two still decide."""
    llm = _ScriptedLLM([RuntimeError("judge flaked")])
    out = await AsiAgent._judge_with_consensus(_fake_agent(llm), _make_request(seed=42), n=3)
    # 3 consensus calls dispatched (1 raised, 2 succeeded); no fresh fallback.
    assert llm.calls == 3
    assert out.text == _make_response().text


@pytest.mark.asyncio
async def test_consensus_returns_lone_success_when_fewer_than_two_succeed() -> None:
    """With <2 successes the lone successful response is returned as-is."""
    only = _resp('{"verdict": "exploited", "confidence": 0.9}')
    llm = _ScriptedLLM([RuntimeError("a"), RuntimeError("b"), only])
    out = await AsiAgent._judge_with_consensus(_fake_agent(llm), _make_request(seed=42), n=3)
    assert out is only
    assert llm.calls == 3  # lone success returned directly, no extra fallback call


@pytest.mark.asyncio
async def test_consensus_falls_back_to_fresh_call_when_all_seats_fail() -> None:
    """All seats failing → one fresh single call so the caller still gets a reply."""
    llm = _ScriptedLLM([RuntimeError("a"), RuntimeError("b"), RuntimeError("c")])
    out = await AsiAgent._judge_with_consensus(_fake_agent(llm), _make_request(seed=42), n=3)
    assert llm.calls == 4  # 3 failed seats + 1 fresh fallback completion
    assert out.text == _make_response().text


@pytest.mark.asyncio
async def test_consensus_real_verdict_outvotes_unparseable_seat() -> None:
    """An unparseable seat is bucketed separately and cannot beat a real majority."""
    import json

    good = '{"verdict": "defended", "confidence": 1.0}'
    llm = _ScriptedLLM([_resp(good), _resp(good), _resp("not json at all")])
    out = await AsiAgent._judge_with_consensus(_fake_agent(llm), _make_request(seed=42), n=3)
    assert json.loads(out.text)["verdict"] == "defended"
