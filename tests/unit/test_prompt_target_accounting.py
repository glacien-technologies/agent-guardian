"""Paid prompt-target usage belongs to the scan that dispatched it."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_guardian import cli as cli_module
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.core.budget import BudgetExhausted
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.cost import token_cost_usd
from agent_guardian.llm.base import BaseLLM, LLMMessage, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.budget_admission import admission_reservation_usd
from agent_guardian.llm.stub import StubLLM
from agent_guardian.llm.usage_tracking import UsageCounter, UsageTrackingLLM

_MODEL = "gemini:gemini-2.5-flash"


class _ObservedLLM(BaseLLM):
    """Deterministic provider double that exposes its observed responses."""

    provider = "gemini"

    def __init__(self, *, prompt_tokens: int, completion_tokens: int) -> None:
        super().__init__(owns_client=False)
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.calls = 0
        self.close_calls = 0
        self.responses: list[LLMResponse] = []

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        response = LLMResponse(
            text="ok",
            model=request.model,
            provider=self.provider,
            usage=LLMUsage(
                prompt_tokens=self.prompt_tokens,
                completion_tokens=self.completion_tokens,
                total_tokens=self.prompt_tokens + self.completion_tokens,
            ),
        )
        self.responses.append(response)
        return response

    async def aclose(self) -> None:
        self.close_calls += 1


def _swarm(
    target: PromptAdapter,
    *,
    usd_cap: float | None = None,
    scanner: BaseLLM | None = None,
) -> SwarmCommander:
    scanner = scanner or StubLLM(default="ok")
    return SwarmCommander(
        config=SwarmConfig(
            scan_id="prompt-target-accounting",
            attacker_model=_MODEL,
            evaluator_model=_MODEL,
            commander_model=_MODEL,
            usd_cap=usd_cap,
        ),
        target=target,
        attacker_llm=scanner,
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=scanner,
    )


@pytest.mark.asyncio
async def test_prompt_target_responses_reach_live_budget_and_final_scan() -> None:
    """Reproduce the live symptom: target logs usage that Scan used to omit."""
    target_provider = _ObservedLLM(prompt_tokens=100, completion_tokens=200)
    scanner_provider = _ObservedLLM(prompt_tokens=30, completion_tokens=20)
    target = PromptAdapter("system", llm=target_provider, model=_MODEL)
    swarm = _swarm(target, scanner=scanner_provider)

    # These are the same PromptAdapter choke point used by recon and attacks.
    await target.call("recon probe", session="recon-agent")
    await target.call("attack probe", session="goal-hijack-agent")
    await swarm.commander_llm.complete(
        LLMRequest(messages=[LLMMessage(role="user", content="scanner work")], model=_MODEL)
    )

    observed = target_provider.responses + scanner_provider.responses
    expected_tokens = sum(response.usage.total_tokens for response in observed)
    expected_cost = sum(
        token_cost_usd(
            _MODEL,
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
        )
        for response in observed
    )

    assert swarm._usage_rollup(include_report_fallback=False) == pytest.approx(
        (expected_tokens, expected_cost)
    )
    assert swarm._build_budget_report().spent_usd == pytest.approx(expected_cost)

    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()

    assert scan.tokens_total == expected_tokens
    assert scan.cost_usd == pytest.approx(round(expected_cost, 4))
    assert scan.budget is not None
    assert scan.budget.spent_usd == pytest.approx(expected_cost)


@pytest.mark.asyncio
async def test_rejected_prompt_target_call_stops_budget_without_dispatch_or_usage() -> None:
    provider = _ObservedLLM(prompt_tokens=100, completion_tokens=200)
    system_prompt = "system"
    user_prompt = "same-size probe"
    input_ceiling = 32 + sum(
        len(content.encode("utf-8")) + len(role) + 32
        for role, content in (("system", system_prompt), ("user", user_prompt))
    )
    reservation = admission_reservation_usd(_MODEL, input_ceiling, 1024)
    observed_cost = token_cost_usd(_MODEL, 100, 200)
    cap = reservation + observed_cost / 2
    target = PromptAdapter(system_prompt, llm=provider, model=_MODEL)
    swarm = _swarm(target, usd_cap=cap)

    await target.call(user_prompt, session="recon-agent")
    with pytest.raises(BudgetExhausted):
        await target.call(user_prompt, session="attack-agent")

    assert provider.calls == 1
    assert swarm._stopped_reason == "budget"
    assert swarm._target_usage.calls == 1
    assert swarm._target_usage.total_tokens == 300
    assert swarm._budget_ledger is not None
    assert [entry.kind for entry in swarm._budget_ledger.entries()] == ["reserve", "commit"]

    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()
    assert scan.stopped_reason == "budget"
    assert scan.tokens_total == 300
    assert scan.cost_usd == pytest.approx(round(observed_cost, 4))
    assert scan.budget is not None
    assert scan.budget.spent_usd == pytest.approx(observed_cost)


@pytest.mark.asyncio
async def test_prewrapped_shared_target_counter_is_rolled_up_once() -> None:
    provider = _ObservedLLM(prompt_tokens=40, completion_tokens=60)
    counter = UsageCounter()
    shared = UsageTrackingLLM(provider, counter=counter)
    target = PromptAdapter("system", llm=shared, model=_MODEL)
    swarm = _swarm(target, scanner=shared)

    assert swarm._target_usage is counter
    await target.call("target work")

    assert counter.total_tokens == 100
    assert swarm._usage_rollup(include_report_fallback=False)[0] == 100
    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()
    assert scan.tokens_total == 100


@pytest.mark.asyncio
async def test_prompt_adapter_closes_original_provider_once_after_instrumentation() -> None:
    provider = _ObservedLLM(prompt_tokens=1, completion_tokens=1)
    target = PromptAdapter("system", llm=provider, model=_MODEL)
    _swarm(target, usd_cap=1.0)

    assert target._llm is not provider
    await target.aclose()

    assert provider.close_calls == 1


def test_cli_closes_prompt_target_provider_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _CloseCountingStub(StubLLM):
        def __init__(self) -> None:
            super().__init__(default="ok")
            self.close_calls = 0

        async def aclose(self) -> None:
            self.close_calls += 1

    clients: dict[str, _CloseCountingStub] = {}

    def build_llm(_model_spec: str, role: str) -> _CloseCountingStub:
        client = _CloseCountingStub()
        clients[role] = client
        return client

    monkeypatch.setattr(cli_module, "build_llm", build_llm)
    monkeypatch.setenv("HOME", str(tmp_path))
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("You are safe.", encoding="utf-8")

    result = CliRunner().invoke(
        cli_module.app,
        [
            "scan",
            "--system-prompt",
            str(prompt),
            "--model",
            "stub",
            "--mode",
            "fast",
            "--max-turns",
            "1",
            "--no-preflight",
            "--no-tui",
            "--no-serve",
            "--no-open",
            "--no-publish",
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.output
    assert clients["target"].close_calls == 1
