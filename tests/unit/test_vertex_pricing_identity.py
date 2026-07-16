"""Resolved Vertex pricing identity through registry and swarm decorators."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

import agent_guardian.llm.budget_admission as budget_admission
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.cost import token_cost_usd
from agent_guardian.llm.base import LLMMessage, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.registry import build_llm, parse_model_spec
from agent_guardian.llm.stub import StubLLM
from agent_guardian.llm.usage_tracking import UsageTrackingLLM
from agent_guardian.llm.vertex import VertexClient

_MODEL = "gemini-3.5-flash"
_RESPONSE_USAGE = LLMUsage(
    prompt_tokens=100,
    completion_tokens=100,
    total_tokens=200,
)


def _request() -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role="user", content="judge this")],
        model=_MODEL,
        max_tokens=1_000,
    )


def _fake_complete() -> Callable[[LLMRequest], Awaitable[LLMResponse]]:
    async def complete(request: LLMRequest) -> LLMResponse:
        assert request.model == _MODEL
        return LLMResponse(
            text='{"verdict":"pass","confidence":0.9,"reasoning":"ok"}',
            model=request.model,
            provider="vertex",
            usage=_RESPONSE_USAGE,
        )

    return complete


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model_spec", "env_location", "expected_location"),
    [
        (f"vertex:{_MODEL}+project=p+location=us-central1", "global", "us-central1"),
        (f"vertex:{_MODEL}+project=p+location=global", "us-central1", "global"),
        (f"vertex:{_MODEL}+project=p", "global", "global"),
        (f"vertex:{_MODEL}+project=p", None, "us-central1"),
    ],
)
async def test_registry_vertex_tracks_resolved_location_with_bare_dispatch_model(
    monkeypatch: pytest.MonkeyPatch,
    model_spec: str,
    env_location: str | None,
    expected_location: str,
) -> None:
    if env_location is None:
        monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    else:
        monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", env_location)

    parsed = parse_model_spec(model_spec)
    assert parsed.model == _MODEL
    llm = build_llm(model_spec, "evaluator")
    assert isinstance(llm, VertexClient)
    monkeypatch.setattr(llm, "complete", _fake_complete())
    request = _request()
    expected_identity = f"vertex:{_MODEL}+location={expected_location}"

    try:
        assert llm.location == expected_location
        assert llm.pricing_model_spec(request) == expected_identity
        tracked = UsageTrackingLLM(llm)
        await tracked.complete(request)
    finally:
        await llm.aclose()

    assert request.model == _MODEL
    assert tracked.counter.priced_cost_usd == pytest.approx(
        token_cost_usd(expected_identity, 100, 100)
    )


@pytest.mark.asyncio
async def test_swarm_panel_wrapper_preserves_vertex_identity_for_admission_and_tracking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Expose the table-rate difference in the reservation as well as the
    # settlement. Production keeps the higher dated admission floor.
    monkeypatch.setattr(budget_admission, "_GEMINI_INPUT_FLOOR_PER_1M", 0.0)
    monkeypatch.setattr(budget_admission, "_GEMINI_OUTPUT_FLOOR_PER_1M", 0.0)
    llm = build_llm(f"vertex:{_MODEL}+project=p+location=us-central1", "attacker")
    assert isinstance(llm, VertexClient)
    monkeypatch.setattr(llm, "complete", _fake_complete())
    target = PromptAdapter("test target", llm=StubLLM(default="ok"), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="vertex-pricing-identity",
            attacker_model=_MODEL,
            evaluator_model=_MODEL,
            commander_model=_MODEL,
            usd_cap=100.0,
        ),
        target=target,
        attacker_llm=llm,
        evaluator_llm=llm,
    )
    request = _request()
    expected_identity = f"vertex:{_MODEL}+location=us-central1"

    try:
        assert swarm._panel_attacker_llm.pricing_model_spec(request) == expected_identity
        await swarm._panel_attacker_llm.complete(request)
    finally:
        await llm.aclose()
        await target.aclose()

    assert request.model == _MODEL
    assert swarm._panel_attacker_usage.priced_cost_usd == pytest.approx(
        token_cost_usd(expected_identity, 100, 100)
    )
    assert swarm._budget_ledger is not None
    reserve, commit = swarm._budget_ledger.entries()
    expected_input_ceiling = 32 + len(b"judge this") + len("user") + 32
    assert reserve.usd == pytest.approx(
        token_cost_usd(expected_identity, expected_input_ceiling, request.max_tokens)
    )
    assert commit.usd == pytest.approx(token_cost_usd(expected_identity, 100, 100))
