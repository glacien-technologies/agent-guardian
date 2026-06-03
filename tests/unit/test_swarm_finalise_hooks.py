"""Unit tests for the Phase-6 finalise scoring/provenance hooks.

Covers the FixesB-swarm wiring:

* #1  — stub-evaluator detection sets ``evaluation_mode`` + ``scoring_valid``
  and forces ``band=NOT_EVALUATED`` (no numeric EXCELLENT for a stub run);
  ``engine`` carries the per-role model specs.
* #5  — a blocklisted destructive tool the target offered (recorded by the
  RoE controller) is synthesized into a HIGH ASI05 finding before scoring.
* #4/#20 — ASI categories with no real coverage (crashed/cancelled agent, or
  every turn egress-refused) are scored not-covered (0.0), never a clean 100.

These are structural tests over the finalise helpers — they don't spin up a
full swarm run.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentReport
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm.base import BaseLLM, LLMRequest, LLMResponse, LLMUsage
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity


class _FakeRealLLM(BaseLLM):
    """A non-stub LLM client (``provider`` != "stub") for real-mode detection."""

    provider = "openai"

    def __init__(self) -> None:  # no httpx client — we never call .complete
        super().__init__(owns_client=False)

    async def complete(self, request: LLMRequest) -> LLMResponse:  # pragma: no cover
        return LLMResponse(
            text="{}",
            model=request.model,
            provider="openai",
            usage=LLMUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        )

    async def aclose(self) -> None:  # pragma: no cover
        return None


class _FakeRoe:
    """Minimal duck-typed RoeController exposing the contract the swarm reads."""

    def __init__(self, *, blocklisted: set[str], egress_refused: int = 0) -> None:
        self._blocklisted = frozenset(blocklisted)
        self._egress_refused = egress_refused

    @property
    def observed_blocklisted_tools(self) -> frozenset[str]:
        return self._blocklisted

    @property
    def egress_refused_turns(self) -> int:
        return self._egress_refused


class _AdapterWithRoe(PromptAdapter):
    def __init__(self, roe: _FakeRoe) -> None:
        super().__init__("t", llm=StubScript().default("ok").build(), model="stub", ref="t")
        self._roe = roe


def _commander(
    *,
    attacker: BaseLLM,
    evaluator: BaseLLM,
    target: PromptAdapter | None = None,
    attacker_model: str = "openai:gpt-4o",
    evaluator_model: str = "openai:gpt-4o",
    commander_model: str = "anthropic:claude",
) -> SwarmCommander:
    tgt = target or PromptAdapter(
        "t", llm=StubScript().default("ok").build(), model="stub", ref="t"
    )
    return SwarmCommander(
        config=SwarmConfig(
            scan_id="finalise-hooks",
            attacker_model=attacker_model,
            evaluator_model=evaluator_model,
            commander_model=commander_model,
        ),
        target=tgt,
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        commander_llm=StubLLM(default="ok"),
    )


def _agent_report(
    asi: AsiCategory, *, turns: int, findings: int, terminated_by: str
) -> AgentReport:
    return AgentReport(
        agent=f"{asi.value.lower()}-agent",
        asi_category=asi,
        findings_count=findings,
        turns=turns,
        duration_seconds=0.1,
        terminated_by=terminated_by,  # type: ignore[arg-type]
    )


# --- #1 evaluation-mode detection ---------------------------------------


def test_detect_evaluation_mode_stub() -> None:
    cmd = _commander(attacker=StubLLM(default="a"), evaluator=StubLLM(default="e"))
    mode, valid = cmd._detect_evaluation_mode()
    assert mode == "stub"
    assert valid is False


def test_detect_evaluation_mode_real() -> None:
    cmd = _commander(attacker=_FakeRealLLM(), evaluator=_FakeRealLLM())
    mode, valid = cmd._detect_evaluation_mode()
    assert mode == "real"
    assert valid is True


def test_detect_evaluation_mode_mixed_is_non_authoritative() -> None:
    cmd = _commander(attacker=_FakeRealLLM(), evaluator=StubLLM(default="e"))
    mode, valid = cmd._detect_evaluation_mode()
    assert mode == "mixed"
    assert valid is False


def test_engine_spec_carries_model_specs() -> None:
    cmd = _commander(attacker=_FakeRealLLM(), evaluator=_FakeRealLLM())
    assert cmd._engine_spec() == {
        "commander": "anthropic:claude",
        "attacker": "openai:gpt-4o",
        "evaluator": "openai:gpt-4o",
    }


# --- #5 blocklisted-tool synthesis --------------------------------------


def test_synthesize_blocklisted_tool_findings() -> None:
    roe = _FakeRoe(blocklisted={"wipe_database", "drop_table"})
    cmd = _commander(
        attacker=_FakeRealLLM(),
        evaluator=_FakeRealLLM(),
        target=_AdapterWithRoe(roe),
    )
    synthesized = cmd._synthesize_blocklisted_tool_findings(existing=[])
    assert len(synthesized) == 2
    assert all(f.severity is Severity.HIGH for f in synthesized)
    assert all(f.asi is AsiCategory.ASI05 for f in synthesized)
    assert all(f.success for f in synthesized)
    tools_named = " ".join(f.summary for f in synthesized)
    assert "wipe_database" in tools_named
    assert "drop_table" in tools_named


def test_synthesize_skips_already_reported_tool() -> None:
    roe = _FakeRoe(blocklisted={"wipe_database"})
    cmd = _commander(
        attacker=_FakeRealLLM(),
        evaluator=_FakeRealLLM(),
        target=_AdapterWithRoe(roe),
    )
    existing = [
        Finding(
            id="f1",
            probe_id="p1",
            asi=AsiCategory.ASI05,
            mitre_atlas=["AML.T0050"],
            csa_category=CsaCategory.AGENT_CRITICAL_SYSTEM_INTERACTION,
            severity=Severity.CRITICAL,
            attempt_count=1,
            success=True,
            confidence=0.9,
            summary="target executed wipe_database on demand",
            created_at=datetime(2026, 5, 27, tzinfo=UTC),
        )
    ]
    # A judge finding already names wipe_database — don't double-count.
    assert cmd._synthesize_blocklisted_tool_findings(existing=existing) == []


def test_synthesize_returns_empty_without_roe() -> None:
    cmd = _commander(attacker=_FakeRealLLM(), evaluator=_FakeRealLLM())
    assert cmd._synthesize_blocklisted_tool_findings(existing=[]) == []


# --- #4/#20 not-covered categories --------------------------------------


def test_not_covered_includes_crashed_and_not_tested_agents() -> None:
    cmd = _commander(attacker=_FakeRealLLM(), evaluator=_FakeRealLLM())
    cmd._agent_reports = [
        # Covered: ran real judged turns.
        _agent_report(AsiCategory.ASI01, turns=5, findings=0, terminated_by="exhausted"),
        # Covered: produced a finding (even with 0 turns recorded).
        _agent_report(AsiCategory.ASI02, turns=0, findings=1, terminated_by="success"),
        # NOT covered: crashed before any judged turn.
        _agent_report(AsiCategory.ASI05, turns=0, findings=0, terminated_by="error"),
        # NOT covered: every turn egress-refused (not_tested).
        _agent_report(AsiCategory.ASI04, turns=0, findings=0, terminated_by="not_tested"),
    ]
    not_covered = cmd._not_covered_categories()
    assert not_covered == {AsiCategory.ASI05, AsiCategory.ASI04}


def test_not_covered_empty_when_all_agents_ran() -> None:
    cmd = _commander(attacker=_FakeRealLLM(), evaluator=_FakeRealLLM())
    cmd._agent_reports = [
        _agent_report(AsiCategory.ASI01, turns=3, findings=0, terminated_by="exhausted"),
    ]
    assert cmd._not_covered_categories() == set()


def test_roe_controller_none_for_plain_adapter() -> None:
    cmd = _commander(attacker=_FakeRealLLM(), evaluator=_FakeRealLLM())
    assert cmd._roe_controller() is None


@pytest.mark.asyncio
async def test_finalise_stub_run_is_not_evaluated() -> None:
    """End-to-end finalise: a stub run yields NOT_EVALUATED + scoring_valid False."""
    from agent_guardian.models.severity import SeverityBand

    cmd = _commander(attacker=StubLLM(default="a"), evaluator=StubLLM(default="e"))
    cmd._start_time = 0.0
    scan = await cmd._phase_finalise()
    assert scan.band is SeverityBand.NOT_EVALUATED
    assert scan.scoring_valid is False
    assert scan.evaluation_mode == "stub"
    assert scan.engine is not None
