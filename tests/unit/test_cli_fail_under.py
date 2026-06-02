"""Cross-cluster contract regression — coverage_grade is gate-able.

This file pins the contract that the swarm + scoring + JSON-report cluster
deliver to the CLI cluster for the ``--fail-under`` gate: when a scan has
``coverage_grade in {"D", "F"}`` the scoring layer must already have forced
``scoring_valid=False`` so the CLI's existing gate at cli.py:2583
refuses to gate-pass on it.

The actual CLI ``--fail-under`` flag implementation lives in the cli-server
cluster — these tests verify the producing-side contract, not the CLI's
exit code (that is the cli-server cluster's edit per the task brief).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_guardian._version import __version__ as _v
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.reports.json_report import emit_json

UTC = UTC


class _FakeRealLLM(BaseLLM):
    provider = "openai"

    def __init__(self) -> None:
        pass

    async def complete(self, request: LLMRequest) -> LLMResponse:  # pragma: no cover
        return LLMResponse(
            text="{}",
            model=request.model,
            provider="openai",
            usage=LLMUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        )

    async def aclose(self) -> None:  # pragma: no cover
        return None


def _commander() -> SwarmCommander:
    target = PromptAdapter("t", llm=StubScript().default("ok").build(), model="stub", ref="t")
    return SwarmCommander(
        config=SwarmConfig(
            scan_id="fail-under",
            attacker_model="openai:gpt-4o",
            evaluator_model="openai:gpt-4o",
            commander_model="anthropic:claude",
        ),
        target=target,
        attacker_llm=_FakeRealLLM(),
        evaluator_llm=_FakeRealLLM(),
        commander_llm=StubLLM(default="ok"),
    )


@pytest.mark.asyncio
async def test_empty_plan_produces_scoring_invalid_and_band_not_evaluated() -> None:
    """An empty plan must yield a scan that the CLI gate will refuse.

    Existing CLI gate (cli.py:2583) refuses when ``not authoritative``
    (== ``not scan.scoring_valid``) -- so as long as the swarm sets
    ``scoring_valid=False`` on the empty-plan path, the cross-cluster
    contract is satisfied without an additional CLI edit.
    """
    cmd = _commander()
    cmd._active_agents = []
    cmd._agent_reports = []
    cmd._start_time = 0.0
    scan = await cmd._phase_finalise()
    # The contract the CLI gate reads:
    assert scan.scoring_valid is False
    assert scan.mode_authoritative is False
    assert scan.band is SeverityBand.NOT_EVALUATED


def test_json_report_emits_coverage_grade_so_external_gates_can_read_it() -> None:
    """External gates (CI / dashboard) need ``coverage_grade`` to refuse F.

    A scan with ``coverage_grade=F`` must surface that signal inside the
    signed JSON report so a downstream gate can refuse to mark the scan
    as authoritative, even when the numeric AIVSS happens to be high.
    """
    scan = Scan(
        id="sc_gate_test_01ABCDEF",
        package_version=_v,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="prompt",
        target_ref="prompt.txt",
        tier=Tier.T2_HIGH,
        # Worst-case for the gate: a high numeric AIVSS retained for debug,
        # but coverage_grade=F + scoring_valid=False making it non-authoritative.
        aivss=100,
        band=SeverityBand.NOT_EVALUATED,
        sub_scores={},
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=1.0,
        cost_usd=0.0,
        mode="full",
        mode_authoritative=False,
        scoring_valid=False,
        coverage_grade="F",
        created_at=datetime(2026, 5, 28, tzinfo=UTC),
    )
    payload = emit_json(scan, sign=False, redact_pii=False)
    assert payload["coverage_grade"] == "F"
    assert payload["scoring_valid"] is False
    assert payload["mode_authoritative"] is False
    # The combined signal a CI gate can refuse on:
    assert payload["band"] == SeverityBand.NOT_EVALUATED.value
