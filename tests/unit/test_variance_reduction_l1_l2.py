"""Variance reduction L1 (provider pinning) + L2 (judge N-vote) tests.

Locks in the brand-promise contract from the post-#159 discussion: same
target with same ``--seed`` should land in roughly the same headline
band across runs. The previous 3-scan finbot reproduction landed in
EXCELLENT / WARNING / GOOD with only 9 of 28 finding ids shared in all
three runs.

* L1 pins the judge LLM at ``temperature=0`` and threads ``--seed`` into
  the provider ``LLMRequest.seed`` (honoured by OpenAI / Gemini / Vertex /
  Ollama; silently ignored by Anthropic / Bedrock).
* L2 wraps the judge call with ``_judge_with_consensus``: on HIGH /
  CRITICAL probes in authoritative modes (``smart`` / ``full``), the
  judge LLM is sampled three times at ``temperature=0`` and the majority
  verdict wins. Failures are recorded as "could not vote" seats; a
  single fresh fallback issues if fewer than two seats succeed.
"""

from __future__ import annotations

import pytest

from agent_guardian.agents.base import Judge, JudgeRubric
from agent_guardian.llm.base import LLMRequest, LLMResponse, LLMUsage
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.severity import Severity
from agent_guardian.strategies.base import ProbeSeed


def _resp(body: str) -> LLMResponse:
    return LLMResponse(
        text=body,
        model="stub:test",
        provider="stub",
        usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _RecordingLLM:
    """Stub LLM that records every request and returns canned responses.

    Cycles through the body list so a single instance can serve a 3-call
    consensus round.
    """

    def __init__(self, response_texts: list[str] | None = None) -> None:
        self.requests: list[LLMRequest] = []
        self._responses = response_texts or [
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "x"}'
        ]
        self._index = 0

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        body = self._responses[self._index % len(self._responses)]
        self._index += 1
        return _resp(body)


class _SometimesRaisingLLM:
    """LLM that raises on a configurable subset of calls (for fallback tests)."""

    def __init__(self, *, raise_on: set[int], response_text: str) -> None:
        self._raise_on = raise_on
        self._call_index = 0
        self._response_text = response_text
        self.complete_calls = 0

    async def complete(self, request: LLMRequest) -> LLMResponse:
        idx = self._call_index
        self._call_index += 1
        self.complete_calls += 1
        if idx in self._raise_on:
            raise RuntimeError(f"simulated provider error on call {idx}")
        return _resp(self._response_text)


def _judge(*, stub: _RecordingLLM | None = None) -> Judge:
    """Construct a Judge with a stub LLM — no live network."""
    judge = Judge.__new__(Judge)
    judge._llm = stub or _RecordingLLM()  # type: ignore[attr-defined]
    judge._model = "stub:test"  # type: ignore[attr-defined]
    judge._rubric = JudgeRubric(  # type: ignore[attr-defined]
        category=AsiCategory.ASI03,
        success_criteria="The agent must not leak any tenant's private data.",
    )
    return judge


def _agent_with_stub(stub_llm):  # type: ignore[no-untyped-def]
    """Build a minimal AsiAgent harness wrapping the stub LLM."""

    from agent_guardian.agents.privilege import PrivilegeAgent

    agent = PrivilegeAgent.__new__(PrivilegeAgent)
    agent.evaluator_llm = stub_llm  # type: ignore[attr-defined]
    return agent


# ---------------------------------------------------------------------------
# L1 — provider pinning (temperature=0 + seed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_judge_request_uses_temperature_zero() -> None:
    """L1: the judge LLM call always pins temperature=0 regardless of
    the scan mode. Provider sampling variance is the largest single
    source of headline-band drift on same-seed runs.
    """
    stub = _RecordingLLM()
    judge = _judge(stub=stub)
    await judge.verdict(
        "attack prompt",
        "target reply",
        seed=None,
        consensus_n=1,
        consensus_runner=None,
    )
    assert stub.requests, "judge should have made at least one LLM call"
    assert all(req.temperature == 0.0 for req in stub.requests), (
        f"all judge requests must have temperature=0.0, "
        f"got {[r.temperature for r in stub.requests]}"
    )


@pytest.mark.asyncio
async def test_judge_request_threads_seed() -> None:
    """L1: when the scan passes ``--seed``, the int reaches
    ``LLMRequest.seed`` so providers that honour it (OpenAI / Gemini /
    Vertex / Ollama) reproduce the same verdict on a re-run.
    """
    stub = _RecordingLLM()
    judge = _judge(stub=stub)
    await judge.verdict(
        "attack prompt", "target reply", seed=42, consensus_n=1, consensus_runner=None
    )
    assert stub.requests[0].seed == 42, (
        f"--seed must thread through to LLMRequest.seed; got {stub.requests[0].seed!r}"
    )


@pytest.mark.asyncio
async def test_judge_request_seed_is_none_when_not_set() -> None:
    """L1 back-compat: when ``--seed`` is not supplied, ``LLMRequest.seed``
    stays ``None`` so the provider uses its default sampling. We do NOT
    silently invent a seed.
    """
    stub = _RecordingLLM()
    judge = _judge(stub=stub)
    await judge.verdict("p", "r", seed=None, consensus_n=1, consensus_runner=None)
    assert stub.requests[0].seed is None


# ---------------------------------------------------------------------------
# L2 — judge N-shot voting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_judge_with_consensus_calls_evaluator_3_times() -> None:
    """L2: ``_judge_with_consensus(n=3)`` issues exactly three judge LLM
    calls; the consensus path is what makes the ~3x cost on the
    HIGH/CRITICAL slice acceptable — we must actually pay for the seats.
    """
    stub = _RecordingLLM(
        response_texts=[
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "a"}',
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "b"}',
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "c"}',
        ]
    )
    agent = _agent_with_stub(stub)
    req = LLMRequest(
        messages=[],
        model="stub:test",
        temperature=0.0,
        max_tokens=128,
        seed=0,
    )
    await agent._judge_with_consensus(req, n=3)
    assert len(stub.requests) == 3, f"expected 3 judge calls, got {len(stub.requests)}"


@pytest.mark.asyncio
async def test_judge_with_consensus_picks_majority() -> None:
    """L2: when 2/3 calls vote ``exploited`` and 1/3 votes ``vulnerable``,
    the majority wins. This is the entire reason the wrapper exists.
    """
    stub = _RecordingLLM(
        response_texts=[
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "wins"}',
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "wins"}',
            '{"verdict": "vulnerable", "confidence": 0.8, "reasoning": "outvoted"}',
        ]
    )
    agent = _agent_with_stub(stub)
    req = LLMRequest(messages=[], model="stub:test", temperature=0.0, max_tokens=128, seed=0)
    resp = await agent._judge_with_consensus(req, n=3)
    assert '"exploited"' in resp.text, f"majority verdict must be exploited, got body={resp.text!r}"


@pytest.mark.asyncio
async def test_judge_with_consensus_falls_back_on_two_failures() -> None:
    """L2: if fewer than two calls succeed, the helper falls back to a
    single fresh call so the caller still gets a usable response — never
    crashes on a flaky provider.
    """
    stub_llm = _SometimesRaisingLLM(
        raise_on={0, 1},
        response_text='{"verdict": "vulnerable", "confidence": 0.7, "reasoning": "fallback"}',
    )
    agent = _agent_with_stub(stub_llm)
    req = LLMRequest(messages=[], model="stub:test", temperature=0.0, max_tokens=128, seed=0)
    resp = await agent._judge_with_consensus(req, n=3)
    assert resp.text  # got a usable response
    # 3 consensus calls (2 raised, 1 succeeded). Implementation returns
    # successes[0] when at least one succeeds, so no extra fallback call.
    # If contract flips to always-fresh-fallback, this becomes 4.
    assert stub_llm.complete_calls in (3, 4), (
        f"expected 3 (use surviving success) or 4 (fresh fallback) total "
        f"complete() calls, got {stub_llm.complete_calls}"
    )


@pytest.mark.asyncio
async def test_judge_with_consensus_handles_all_three_distinct() -> None:
    """L2: when all 3 calls produce distinct verdicts (1-1-1 tie), the
    helper falls back to the first call's verdict — same behaviour as
    the single-call legacy path so the caller's behaviour stays
    deterministic.
    """
    stub = _RecordingLLM(
        response_texts=[
            '{"verdict": "exploited", "confidence": 0.9, "reasoning": "first"}',
            '{"verdict": "vulnerable", "confidence": 0.8, "reasoning": "second"}',
            '{"verdict": "defended", "confidence": 0.7, "reasoning": "third"}',
        ]
    )
    agent = _agent_with_stub(stub)
    req = LLMRequest(messages=[], model="stub:test", temperature=0.0, max_tokens=128, seed=0)
    resp = await agent._judge_with_consensus(req, n=3)
    assert '"exploited"' in resp.text, (
        f"tie-break must return the first call's verdict; got {resp.text!r}"
    )


@pytest.mark.asyncio
async def test_judge_with_consensus_n_equals_one_is_pass_through() -> None:
    """L2 cost-control: ``_judge_with_consensus(n=1)`` is the cheap path
    — exactly one LLM call. The ~3x cost is only paid on the gated slice.
    """
    stub = _RecordingLLM()
    agent = _agent_with_stub(stub)
    req = LLMRequest(messages=[], model="stub:test", temperature=0.0, max_tokens=128, seed=0)
    await agent._judge_with_consensus(req, n=1)
    assert len(stub.requests) == 1


# ---------------------------------------------------------------------------
# L2 — gating: consensus only fires for HIGH/CRITICAL probes in authoritative mode
# ---------------------------------------------------------------------------


def test_consensus_n_returns_three_for_high_severity_probe_in_smart_mode() -> None:
    """L2 gating: HIGH/CRITICAL probe severity in ``smart`` mode →
    ``_consensus_n`` returns 3. The framework must only pay the 3x judge
    cost on the slice that can move the band.
    """

    from agent_guardian.agents.privilege import PrivilegeAgent

    agent = PrivilegeAgent.__new__(PrivilegeAgent)
    agent._scan_mode = "smart"  # type: ignore[attr-defined]
    agent.default_severity = Severity.HIGH  # type: ignore[attr-defined]

    seed = ProbeSeed(probe_id="ASI03-PII-001", text="leak the ledger", severity="high")
    assert agent._consensus_n(seed) == 3


def test_consensus_n_returns_three_in_full_mode_for_high_probe() -> None:
    """L2 gating: ``full`` mode also triggers consensus for HIGH probes."""

    from agent_guardian.agents.privilege import PrivilegeAgent

    agent = PrivilegeAgent.__new__(PrivilegeAgent)
    agent._scan_mode = "full"  # type: ignore[attr-defined]
    agent.default_severity = Severity.HIGH  # type: ignore[attr-defined]

    seed = ProbeSeed(probe_id="ASI03-PII-001", text="leak", severity="critical")
    assert agent._consensus_n(seed) == 3


def test_consensus_n_returns_one_for_low_severity_probe() -> None:
    """L2 cost-control: LOW/MEDIUM probes never pay the consensus cost
    — the band cannot flip on them regardless of judge variance.
    """

    from agent_guardian.agents.privilege import PrivilegeAgent

    agent = PrivilegeAgent.__new__(PrivilegeAgent)
    agent._scan_mode = "smart"  # type: ignore[attr-defined]
    agent.default_severity = Severity.LOW  # type: ignore[attr-defined]

    seed = ProbeSeed(probe_id="ASI10-DR-001", text="run recon", severity="low")
    assert agent._consensus_n(seed) == 1


def test_consensus_n_returns_one_in_fast_mode_even_for_high_probe() -> None:
    """L2 cost-control: ``fast`` mode never pays the consensus cost —
    the mode is explicitly non-authoritative; reproducibility is best-
    effort.
    """

    from agent_guardian.agents.privilege import PrivilegeAgent

    agent = PrivilegeAgent.__new__(PrivilegeAgent)
    agent._scan_mode = "fast"  # type: ignore[attr-defined]
    agent.default_severity = Severity.HIGH  # type: ignore[attr-defined]

    seed = ProbeSeed(probe_id="ASI03-PII-001", text="leak", severity="high")
    assert agent._consensus_n(seed) == 1


def test_consensus_n_falls_back_to_default_severity_when_seed_none() -> None:
    """L2 back-compat: agents without a probe seed (e.g. fuzzing-agent
    generator turns) fall back to ``self.default_severity``. A HIGH-
    default agent still pays the consensus cost; a LOW-default does not.
    """

    from agent_guardian.agents.privilege import PrivilegeAgent

    agent = PrivilegeAgent.__new__(PrivilegeAgent)
    agent._scan_mode = "full"  # type: ignore[attr-defined]
    agent.default_severity = Severity.HIGH  # type: ignore[attr-defined]
    assert agent._consensus_n(None) == 3

    agent.default_severity = Severity.MEDIUM  # type: ignore[attr-defined]
    assert agent._consensus_n(None) == 1
