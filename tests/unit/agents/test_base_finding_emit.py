"""Unit tests for the per-finding ``finding`` producer at
:mod:`agent_guardian.agents.base`.

SSE follow-up (2026-06-04) — :meth:`AsiAgent._emit_finding` is called from
the per-turn loop in :meth:`AsiAgent.run` immediately after
``memory.write_finding`` accepts a ``verdict=='fail'`` finding, so the
dashboard's Findings tab can live-append the row (probes already
live-appended; findings previously needed an F5).

Acceptance:

* The emitted event uses the ``"finding"`` :class:`EventKind` literal so
  it is wire-compatible with the scan-store fan-out + the dashboard's
  ``live-append.js`` ``finding`` handler.
* The payload carries every field the client-side ``buildFindingRow``
  reader keys off: ``{finding_id, id, severity, asi, category, agent,
  probe_id, summary, turn}``.
* ``event.asi`` is set at the top level too (so disk replay / the SSE
  wire carry the ASI both places).
* A missing observer (``self._observer = None``) is a silent no-op.
* An observer that raises does NOT bubble out of ``_emit_finding``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.llm.stub import StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity


def _stub() -> object:
    return StubScript().default("ok").build()


def _make_agent() -> DriftAgent:
    return DriftAgent(
        attacker_llm=_stub(),
        evaluator_llm=_stub(),
        attacker_model="stub-model",
        evaluator_model="stub-model",
        budget=AgentBudget(tokens_remaining=50_000, wall_seconds_remaining=60.0, max_turns=2),
    )


def _make_finding() -> Finding:
    return Finding(
        id="f-deadbeef0001",
        probe_id="ASI10-DRIFT-003",
        asi=AsiCategory.ASI10,
        mitre_atlas=["AML.T0054"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=2,
        success=True,
        confidence=0.88,
        summary="objective drift after multi-turn reframing",
        created_at=datetime(2026, 6, 4, 9, 0, 0, tzinfo=UTC),
    )


def test_emit_finding_payload_has_all_client_fields() -> None:
    """The emitted event carries the kind + the full row payload contract."""
    captured: list[SwarmEvent] = []
    agent = _make_agent()
    agent._observer = captured.append

    finding = _make_finding()
    agent._emit_finding(finding=finding, agent_name="drift-agent", turn=2)

    assert len(captured) == 1
    evt = captured[0]
    assert evt.kind == "finding"
    # ASI surfaced at the SwarmEvent top level too (disk-replay + wire).
    assert evt.asi == AsiCategory.ASI10
    assert evt.agent == "drift-agent"

    payload = evt.payload
    assert isinstance(payload, dict)
    for required in (
        "finding_id",
        "id",
        "severity",
        "asi",
        "category",
        "agent",
        "probe_id",
        "summary",
        "turn",
    ):
        assert required in payload, f"finding payload missing key '{required}': {payload!r}"

    assert payload["finding_id"] == "f-deadbeef0001"
    assert payload["id"] == "f-deadbeef0001"
    assert payload["severity"] == "high"
    assert payload["asi"] == "ASI10"
    assert payload["category"] == "goal-instruction-manipulation"
    assert payload["agent"] == "drift-agent"
    assert payload["probe_id"] == "ASI10-DRIFT-003"
    assert payload["summary"] == "objective drift after multi-turn reframing"
    assert payload["turn"] == 2


def test_emit_finding_no_observer_is_silent_noop() -> None:
    """Legacy callers without an injected observer must not crash."""
    agent = _make_agent()
    assert agent._observer is None
    # Must not raise.
    agent._emit_finding(finding=_make_finding(), agent_name="drift-agent", turn=1)


def test_emit_finding_observer_raising_is_swallowed() -> None:
    """A sick observer must never break the attack loop."""

    def _bad(event: SwarmEvent) -> None:
        raise RuntimeError("observer is on fire")

    agent = _make_agent()
    agent._observer = _bad
    # Must not raise.
    agent._emit_finding(finding=_make_finding(), agent_name="drift-agent", turn=1)
