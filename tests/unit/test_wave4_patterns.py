"""Tests for M2 Wave 4: N-version race (P1), model race (P4), triage (P3), critic (P6)."""

from __future__ import annotations

import asyncio

import pytest

from agent_guardian.adapters.base import TargetAdapter, TargetFingerprint
from agent_guardian.agents.critic import CriticAgent
from agent_guardian.core.model_race import ModelEndpoint, ModelRacer
from agent_guardian.core.pov.harness import IndicatorKind, PoVScript, SuccessIndicator
from agent_guardian.core.pov.runner import PoVRunner
from agent_guardian.core.race import race_first_success
from agent_guardian.core.triage import RawFinding, TwoTierTriage
from agent_guardian.llm.base import LLMRequest, LLMUsage
from agent_guardian.llm.stub import StubLLM

# ---------------------------------------------------------------------------
# P1 — race_first_success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_race_first_validated_success_wins() -> None:
    async def fast_bad() -> int:
        await asyncio.sleep(0.01)
        return 1  # fails validator

    async def slow_good() -> int:
        await asyncio.sleep(0.05)
        return 2  # passes validator

    outcome = await race_first_success(
        {"fast_bad": fast_bad, "slow_good": slow_good},
        validator=lambda r: r == 2,
    )
    assert outcome.winner == 2
    assert outcome.winner_label == "slow_good"


@pytest.mark.asyncio
async def test_race_no_validated_success_returns_none() -> None:
    async def a() -> int:
        return 1

    outcome = await race_first_success({"a": a}, validator=lambda r: False)
    assert outcome.winner is None


@pytest.mark.asyncio
async def test_race_counts_errors() -> None:
    async def boom() -> int:
        raise RuntimeError("nope")

    async def good() -> int:
        return 5

    outcome = await race_first_success({"boom": boom, "good": good}, validator=lambda r: True)
    assert outcome.winner == 5
    assert outcome.errors == 1


# ---------------------------------------------------------------------------
# P4 — ModelRacer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_model_racer_picks_validated_response() -> None:
    refuser = StubLLM(default="I cannot help with that")
    complier = StubLLM(default="Sure, here is the answer")
    panel = [
        ModelEndpoint(refuser, "refuser-model"),
        ModelEndpoint(complier, "complier-model"),
    ]
    req = LLMRequest(messages=[], model="placeholder")
    result = await ModelRacer().race(req, panel, validator=lambda resp: "Sure" in resp.text)
    assert result.response is not None
    assert "Sure" in result.response.text
    assert result.winner_label == "stub:complier-model"


# ---------------------------------------------------------------------------
# P3 — TwoTierTriage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_triage_deep_analyzes_only_top_slice() -> None:
    findings = [RawFinding(f"f{i}", summary=f"s{i}", asi="ASI01") for i in range(10)]

    async def cheap(f: RawFinding) -> float:
        # score by trailing index so f9 is highest.
        return int(f.finding_id[1:]) / 10.0

    deep_calls: list[str] = []

    async def deep(f: RawFinding) -> tuple[float, str]:
        deep_calls.append(f.finding_id)
        return 0.95, "deep ok"

    triage = TwoTierTriage(cheap_scorer=cheap, deep_analyst=deep)
    out = await triage.run(findings, top_k_pct=0.20)
    # 20% of 10 = 2 deep-analyzed, and they're the two highest cheap scores.
    assert sum(1 for a in out if a.deep_analyzed) == 2
    assert set(deep_calls) == {"f9", "f8"}


@pytest.mark.asyncio
async def test_triage_respects_budget_cap() -> None:
    findings = [RawFinding(f"f{i}", summary="s", asi="ASI01") for i in range(10)]

    async def cheap(f: RawFinding) -> float:
        return 0.5

    async def deep(f: RawFinding) -> tuple[float, str]:
        return 0.9, ""

    # top_k_pct would allow 5, but budget only affords 2 deep passes @ $0.50.
    triage = TwoTierTriage(cheap_scorer=cheap, deep_analyst=deep, deep_cost_usd=0.50)
    out = await triage.run(findings, top_k_pct=0.50, budget_cap_usd=1.00)
    assert sum(1 for a in out if a.deep_analyzed) == 2


# ---------------------------------------------------------------------------
# P6 — CriticAgent
# ---------------------------------------------------------------------------


class _Target(TargetAdapter):
    mode = "code"

    def __init__(self, reply: str) -> None:
        super().__init__()
        self._fingerprint = TargetFingerprint(mode="code", ref="t")
        self._reply = reply

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        return self._reply


@pytest.mark.asyncio
async def test_critic_accepts_reproducible_high_quality_finding() -> None:
    target = _Target("CANARY-9 leaked")
    script = PoVScript(
        scenario_id="c1",
        indicator=SuccessIndicator(IndicatorKind.CONTAINS, "CANARY-9"),
        trigger=["echo"],
    )

    async def rubric(_summary: str) -> dict[str, float]:
        return {"evidence": 0.9, "specificity": 0.8, "novelty": 0.7, "fp_risk": 0.1}

    critic = CriticAgent(rubric_scorer=rubric)
    verdict = await critic.critique(finding_summary="leak", script=script, target=target, n=5)
    assert verdict.accept is True
    assert verdict.reliability == 1.0


@pytest.mark.asyncio
async def test_critic_rejects_unreproducible_finding() -> None:
    target = _Target("I refuse")
    script = PoVScript(
        scenario_id="c2",
        indicator=SuccessIndicator(IndicatorKind.CONTAINS, "CANARY-9"),
        trigger=["echo"],
    )

    async def rubric(_summary: str) -> dict[str, float]:
        return {"evidence": 0.9, "specificity": 0.9, "novelty": 0.9, "fp_risk": 0.0}

    critic = CriticAgent(rubric_scorer=rubric)
    verdict = await critic.critique(finding_summary="leak", script=script, target=target, n=5)
    assert verdict.accept is False
    assert "reliability" in (verdict.rejection_reason or "")


@pytest.mark.asyncio
async def test_critic_rejects_high_false_positive_risk() -> None:
    target = _Target("CANARY-9 leaked")
    script = PoVScript(
        scenario_id="c3",
        indicator=SuccessIndicator(IndicatorKind.CONTAINS, "CANARY-9"),
        trigger=["echo"],
    )

    async def rubric(_summary: str) -> dict[str, float]:
        return {"evidence": 0.9, "specificity": 0.9, "novelty": 0.9, "fp_risk": 0.9}

    critic = CriticAgent(rubric_scorer=rubric)
    verdict = await critic.critique(finding_summary="leak", script=script, target=target, n=5)
    assert verdict.accept is False
    assert "false-positive" in (verdict.rejection_reason or "")


@pytest.mark.asyncio
async def test_critic_rejects_when_no_pov() -> None:
    async def rubric(_summary: str) -> dict[str, float]:
        return {"evidence": 1.0, "specificity": 1.0, "novelty": 1.0, "fp_risk": 0.0}

    critic = CriticAgent(rubric_scorer=rubric)
    verdict = await critic.critique(finding_summary="leak")
    assert verdict.accept is False
    assert "no reproducible PoV" in (verdict.rejection_reason or "")


# Keep the LLMUsage / PoVRunner imports meaningful (API-drift canary).
_ = (LLMUsage, PoVRunner)
