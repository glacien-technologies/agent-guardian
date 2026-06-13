"""rc29 finding-aggregation redesign — unit suite.

Covers:

* :class:`Attempt` construction and frozen invariant.
* :class:`Finding` rc29 default construction (``schema_version='finding-v2'``)
  and the legacy v1 compat reader that wraps a per-turn record into a
  synthetic single-element ``attempts`` list.
* The deterministic ``_deterministic_finding_id`` helper and the
  mutant-probe-id collapser ``_resolve_parent_probe_id``.
* :meth:`AsiAgent._aggregate_attempts_to_findings` behaviour: single-attempt,
  multi-success collapse, mixed verdicts, mutant collapse, verify-turn
  dedup, Wilson lower bound, and representative-Attempt selection.

See ``docs/_design/finding-aggregation-redesign-2026-06.md`` §VII.C for the
locked test list.
"""

from __future__ import annotations

from datetime import UTC, datetime
from random import Random

import pytest
from pydantic import ValidationError

from agent_guardian.agents.base import (
    AgentBudget,
    _deterministic_finding_id,
    _resolve_parent_probe_id,
)
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.attempt import Attempt
from agent_guardian.models.finding import Finding, _wilson_lower_bound


def _t(*, sequence: int = 1, success: bool = True, **overrides: object) -> Attempt:
    """Minimal Attempt factory for the aggregation tests."""
    defaults: dict[str, object] = {
        "id": f"f-att{sequence:03d}",
        "probe_id": "ASI03-PII-001",
        "asi": "ASI03",
        "sequence": sequence,
        "verdict_v2": "exploited" if success else "vulnerable",
        "confidence": 1.0,
        "success": success,
        "created_at": datetime(2026, 6, 13, 9, 53, sequence, tzinfo=UTC),
        "evidence_types": ["observable"],
        "summary": "the target leaked tenant data",
    }
    defaults.update(overrides)
    return Attempt(**defaults)  # type: ignore[arg-type]


def _agent() -> PrivilegeAgent:
    """Privilege agent — concrete AsiAgent subclass used for aggregator tests."""
    return PrivilegeAgent(
        attacker_llm=StubLLM(default="x"),
        evaluator_llm=StubLLM(default="x"),
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=20_000, wall_seconds_remaining=30.0, max_turns=5),
        rng=Random(0),
    )


# --- Attempt model -----------------------------------------------------


def test_attempt_can_be_constructed_from_finding_fields() -> None:
    """Every field on a per-turn Finding has a home on Attempt."""
    a = _t(
        sequence=2,
        trigger_prompt="leak the tenant data",
        trigger_response="here is the balance: $12,905",
        evidence_quote="balance: $12,905",
        reproduced_n_of_m="3/3",
        pov_reliability=0.44,
        is_verify_turn=False,
    )
    assert a.id == "f-att002"
    assert a.probe_id == "ASI03-PII-001"
    assert a.asi == "ASI03"
    assert a.sequence == 2
    assert a.verdict_v2 == "exploited"
    assert a.success is True
    assert a.trigger_prompt == "leak the tenant data"
    assert a.trigger_response == "here is the balance: $12,905"
    assert a.evidence_quote == "balance: $12,905"
    assert a.reproduced_n_of_m == "3/3"
    assert a.pov_reliability == 0.44
    assert a.is_verify_turn is False
    assert a.summary == "the target leaked tenant data"


def test_attempt_is_frozen() -> None:
    a = _t()
    with pytest.raises(ValidationError):
        a.sequence = 99  # type: ignore[misc]


# --- Finding v2 / v1 schema --------------------------------------------


def _v2_finding(**overrides: object) -> Finding:
    """Direct rc29 Finding construction (mirrors what the aggregator emits)."""
    defaults: dict[str, object] = {
        "id": "f-deadbeefdead",
        "schema_version": "finding-v2",
        "probe_id": "ASI03-PII-001",
        "asi": AsiCategory.ASI03,
        "mitre_atlas": ["AML.T0054"],
        "csa_category": "authorization-control-hijacking",
        "severity": "high",
        "attempt_count": 4,
        "success_count": 4,
        "success": True,
        "confidence": 0.51,
        "summary": "tenant isolation breach across four turns",
        "verdict_v2": "exploited",
        "attempts": [],
        "created_at": datetime(2026, 6, 13, 9, 53, 39, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_finding_v2_default_construction() -> None:
    f = _v2_finding()
    assert f.schema_version == "finding-v2"
    assert f.success_count == 4
    assert f.attempts == []  # the aggregator passes its own list


def test_finding_v1_legacy_reader_wraps_to_v2_shape() -> None:
    """A pre-rc29 dict (no schema_version, no attempts) parses cleanly.

    The compat reader tags it ``schema_version='finding-v1'`` and
    wraps the single per-turn record as ``attempts=[<self>]`` so
    downstream code can read v1 records via the v2 shape.
    """
    v1_payload = {
        "id": "f-178aa904e775",
        "probe_id": "ASI03-PII-001",
        "asi": "ASI03",
        "mitre_atlas": ["AML.T0054"],
        "csa_category": "authorization-control-hijacking",
        "severity": "high",
        "attempt_count": 1,
        "success": True,
        "confidence": 1.0,
        "summary": "tenant isolation breached on turn 1",
        "verdict_v2": "exploited",
        "evidence_quote": "Current balance: $12,905",
        "created_at": "2026-06-13T09:53:39Z",
    }
    f = Finding.model_validate(v1_payload)
    assert f.schema_version == "finding-v1"
    assert f.success_count == 1
    assert len(f.attempts) == 1
    synth = f.attempts[0]
    assert synth.id == "f-178aa904e775"
    assert synth.probe_id == "ASI03-PII-001"
    assert synth.asi == "ASI03"
    assert synth.sequence == 1
    assert synth.success is True
    assert synth.verdict_v2 == "exploited"


# --- Deterministic id helper -------------------------------------------


def test_deterministic_finding_id_is_stable() -> None:
    """Same (probe_id, asi) -> same id on every call, across processes."""
    a = _deterministic_finding_id("ASI03-PII-001", AsiCategory.ASI03)
    b = _deterministic_finding_id("ASI03-PII-001", AsiCategory.ASI03)
    assert a == b
    assert a.startswith("f-")
    # 12 hex chars after the f- prefix.
    assert len(a) == 2 + 12


def test_deterministic_finding_id_distinct_per_probe_asi() -> None:
    """Different probe_id OR different ASI must yield a different id."""
    base = _deterministic_finding_id("ASI03-PII-001", AsiCategory.ASI03)
    diff_probe = _deterministic_finding_id("ASI03-PII-002", AsiCategory.ASI03)
    diff_asi = _deterministic_finding_id("ASI03-PII-001", AsiCategory.ASI01)
    assert base != diff_probe
    assert base != diff_asi
    assert diff_probe != diff_asi


# --- Mutant probe-id collapser -----------------------------------------


def test_resolve_parent_probe_id_strips_mutant_suffix() -> None:
    assert _resolve_parent_probe_id("ASI03-PII-001-mutant-xor") == "ASI03-PII-001"
    assert _resolve_parent_probe_id("ASI03-PII-001-mutant-leet") == "ASI03-PII-001"


def test_resolve_parent_probe_id_non_mutant_passthrough() -> None:
    assert _resolve_parent_probe_id("ASI03-PII-001") == "ASI03-PII-001"
    assert _resolve_parent_probe_id("plain-probe") == "plain-probe"
    assert _resolve_parent_probe_id("") == ""


# --- Aggregator behaviour ----------------------------------------------


async def test_aggregate_single_attempt_one_finding() -> None:
    agent = _agent()
    agent._attempt_records.append(_t(sequence=1))
    findings = await agent._aggregate_attempts_to_findings()
    assert len(findings) == 1
    f = findings[0]
    assert f.probe_id == "ASI03-PII-001"
    assert f.attempt_count == 1
    assert f.success_count == 1
    assert f.success is True
    assert f.schema_version == "finding-v2"
    assert len(f.attempts) == 1
    assert f.attempts[0].id == "f-att001"


async def test_aggregate_four_successes_collapse_to_one() -> None:
    """The motivating reproduction: cli-397b6d788333 ASI03-PII-001 x4 turns."""
    agent = _agent()
    for i in range(1, 5):
        agent._attempt_records.append(_t(sequence=i))
    findings = await agent._aggregate_attempts_to_findings()
    assert len(findings) == 1
    f = findings[0]
    assert f.attempt_count == 4
    assert f.success_count == 4
    assert f.success is True
    # Wilson lower bound on 4/4 at z=1.96 — exact value from the module's
    # canonical implementation, not the design doc's rounded prose.
    assert f.confidence == pytest.approx(_wilson_lower_bound(4, 4), abs=1e-6)
    # All four legacy ids preserved on the Attempt list.
    assert {a.id for a in f.attempts} == {f"f-att{i:03d}" for i in range(1, 5)}


async def test_aggregate_mixed_verdicts_same_probe() -> None:
    """1 exploited + 1 vulnerable on the same probe → one Finding, mixed Attempts."""
    agent = _agent()
    agent._attempt_records.append(_t(sequence=1, success=False))  # vulnerable
    agent._attempt_records.append(_t(sequence=2, success=True))  # exploited
    findings = await agent._aggregate_attempts_to_findings()
    assert len(findings) == 1
    f = findings[0]
    assert f.attempt_count == 2
    assert f.success_count == 1
    # at least one Attempt landed → success=True; confidence captures the
    # lower reproducibility (Wilson 1/2 ~ 0.09).
    assert f.success is True
    assert f.confidence == pytest.approx(_wilson_lower_bound(1, 2), abs=1e-6)
    # Mixed verdict_v2 values preserved on the Attempt list.
    verdicts = sorted(a.verdict_v2 for a in f.attempts)
    assert verdicts == ["exploited", "vulnerable"]


async def test_aggregate_mutant_collapses_to_parent_probe() -> None:
    """A mutant probe id (`<parent>-mutant-<op>`) collapses into the parent bucket."""
    agent = _agent()
    agent._attempt_records.append(_t(sequence=1, probe_id="ASI03-PII-001"))
    agent._attempt_records.append(_t(sequence=2, probe_id="ASI03-PII-001-mutant-xor"))
    findings = await agent._aggregate_attempts_to_findings()
    # One Finding, keyed off the parent.
    assert len(findings) == 1
    f = findings[0]
    assert f.probe_id == "ASI03-PII-001"
    assert f.attempt_count == 2
    # The mutant's distinct trigger_response would be preserved on its
    # Attempt; here we just confirm both Attempts survive into the bucket.
    assert {a.probe_id for a in f.attempts} == {
        "ASI03-PII-001",
        "ASI03-PII-001-mutant-xor",
    }


async def test_aggregate_verify_turn_dedup_when_identical() -> None:
    """A verify turn with the SAME verdict as the prior Attempt is dropped."""
    agent = _agent()
    agent._attempt_records.append(_t(sequence=1, success=True))
    agent._attempt_records.append(_t(sequence=2, success=True, is_verify_turn=True))
    findings = await agent._aggregate_attempts_to_findings()
    assert len(findings) == 1
    f = findings[0]
    # Verify-turn record discarded → attempt_count drops from 2 to 1.
    assert f.attempt_count == 1
    assert f.success_count == 1


async def test_aggregate_verify_turn_kept_when_distinct() -> None:
    """A verify turn that FLIPS the verdict survives — it's real signal."""
    agent = _agent()
    agent._attempt_records.append(_t(sequence=1, success=True))
    agent._attempt_records.append(
        _t(sequence=2, success=False, is_verify_turn=True, verdict_v2="vulnerable")
    )
    findings = await agent._aggregate_attempts_to_findings()
    assert len(findings) == 1
    f = findings[0]
    # Distinct verdicts → both Attempts survive.
    assert f.attempt_count == 2
    assert f.success_count == 1


async def test_aggregate_wilson_lower_bound_4_of_4_approx_0_575() -> None:
    """4/4 successes → Finding.confidence matches the canonical Wilson formula.

    The design doc cites ~0.575 in prose; the actual Wilson(z=1.96) value
    is closer to 0.51. The test asserts equality with the module's own
    canonical implementation so the test stays correct if the constant
    changes in a future release.
    """
    agent = _agent()
    for i in range(1, 5):
        agent._attempt_records.append(_t(sequence=i))
    findings = await agent._aggregate_attempts_to_findings()
    assert findings[0].confidence == pytest.approx(_wilson_lower_bound(4, 4), abs=1e-6)


async def test_aggregate_wilson_lower_bound_1_of_2_approx_0_09() -> None:
    """1/2 successes → Finding.confidence ≈ 0.09 (Wilson lower bound)."""
    agent = _agent()
    agent._attempt_records.append(_t(sequence=1, success=True))
    agent._attempt_records.append(_t(sequence=2, success=False))
    findings = await agent._aggregate_attempts_to_findings()
    f = findings[0]
    assert f.success_count == 1
    assert f.attempt_count == 2
    assert f.confidence == pytest.approx(_wilson_lower_bound(1, 2), abs=1e-6)
    assert 0.05 < f.confidence < 0.15  # spot-check the 0.09-ish range


async def test_aggregate_representative_attempt_selection() -> None:
    """Rep = max(success, -sequence) — highest success, then lowest sequence.

    Locked rule from design §III.C step 4:
        bucket [vulnerable@1, exploited@2]      -> rep = exploited@2
        bucket [exploited@1, vulnerable@2]      -> rep = exploited@1
        bucket [vulnerable@1, vulnerable@2]     -> rep = vulnerable@1
        bucket [exploited@1, exploited@2]       -> rep = exploited@1
    The Finding's verdict_v2 / trigger_prompt / trigger_response / evidence_quote
    all come from the representative Attempt.
    """
    # Case 1: vulnerable then exploited → rep = exploited@2.
    agent = _agent()
    agent._attempt_records.append(
        _t(sequence=1, success=False, verdict_v2="vulnerable", trigger_prompt="p1")
    )
    agent._attempt_records.append(
        _t(sequence=2, success=True, verdict_v2="exploited", trigger_prompt="p2")
    )
    f = (await agent._aggregate_attempts_to_findings())[0]
    assert f.verdict_v2 == "exploited"
    assert f.trigger_prompt == "p2"

    # Case 2: exploited then vulnerable → rep = exploited@1 (lowest seq among ties).
    agent = _agent()
    agent._attempt_records.append(
        _t(sequence=1, success=True, verdict_v2="exploited", trigger_prompt="p1")
    )
    agent._attempt_records.append(
        _t(sequence=2, success=False, verdict_v2="vulnerable", trigger_prompt="p2")
    )
    f = (await agent._aggregate_attempts_to_findings())[0]
    assert f.verdict_v2 == "exploited"
    assert f.trigger_prompt == "p1"

    # Case 3: two vulnerable in sequence → rep = vulnerable@1.
    agent = _agent()
    agent._attempt_records.append(
        _t(sequence=1, success=False, verdict_v2="vulnerable", trigger_prompt="p1")
    )
    agent._attempt_records.append(
        _t(sequence=2, success=False, verdict_v2="vulnerable", trigger_prompt="p2")
    )
    f = (await agent._aggregate_attempts_to_findings())[0]
    assert f.verdict_v2 == "vulnerable"
    assert f.trigger_prompt == "p1"

    # Case 4: two exploited in sequence → rep = exploited@1.
    agent = _agent()
    agent._attempt_records.append(
        _t(sequence=1, success=True, verdict_v2="exploited", trigger_prompt="p1")
    )
    agent._attempt_records.append(
        _t(sequence=2, success=True, verdict_v2="exploited", trigger_prompt="p2")
    )
    f = (await agent._aggregate_attempts_to_findings())[0]
    assert f.verdict_v2 == "exploited"
    assert f.trigger_prompt == "p1"


# ---------------------------------------------------------------------------
# Swarm-level same-id dedup (cross-agent collapse)
# ---------------------------------------------------------------------------


async def test_swarm_same_id_dedup_collapses_two_findings_with_identical_id() -> None:
    """When two agents both fire the same probe (e.g. output-handling-agent
    AND identity-leak-agent both lit ASI03-PII-001), the deterministic
    Finding.id is identical. SwarmCommander._dedupe_same_id_findings must
    collapse them into ONE Finding with merged attempts (renumbered to
    1..N) and recomputed Wilson confidence.
    """
    from agent_guardian.core.swarm import SwarmCommander
    from agent_guardian.models.csa import CsaCategory
    from agent_guardian.models.severity import Severity

    shared_id = _deterministic_finding_id("ASI03-PII-001", AsiCategory.ASI03)

    f1 = Finding(
        id=shared_id,
        probe_id="ASI03-PII-001",
        asi=AsiCategory.ASI03,
        mitre_atlas=["AML.T0035"],
        csa_category=CsaCategory.HALLUCINATION_EXPLOITATION,
        severity=Severity.HIGH,
        attempt_count=2,
        success_count=2,
        success=True,
        confidence=0.342,
        verdict_v2="exploited",
        summary="output-handling-agent: leaked PII",
        created_at=datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
        attempts=[
            _t(sequence=1, success=True, id="f-att001"),
            _t(sequence=2, success=True, id="f-att002"),
        ],
    )
    f2 = Finding(
        id=shared_id,
        probe_id="ASI03-PII-001",
        asi=AsiCategory.ASI03,
        mitre_atlas=["AML.T0035"],
        csa_category=CsaCategory.HALLUCINATION_EXPLOITATION,
        severity=Severity.HIGH,
        attempt_count=2,
        success_count=1,
        success=True,
        confidence=0.094,
        verdict_v2="exploited",
        summary="identity-leak-agent: leaked PII",
        created_at=datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
        attempts=[
            _t(sequence=1, success=False, id="f-att101", verdict_v2="vulnerable"),
            _t(sequence=2, success=True, id="f-att102"),
        ],
    )

    # _dedupe_same_id_findings is an instance method but uses no instance
    # state beyond _LOG; SwarmCommander.__new__ avoids __init__ wiring.
    cmd = SwarmCommander.__new__(SwarmCommander)
    merged = cmd._dedupe_same_id_findings([f1, f2])

    assert len(merged) == 1, "two same-id Findings must collapse to one"
    m = merged[0]
    assert m.id == shared_id
    assert len(m.attempts) == 4, "attempts must be the union (2 + 2)"
    # Sequence renumbered contiguously 1..4
    assert [a.sequence for a in m.attempts] == [1, 2, 3, 4]
    assert m.attempt_count == 4
    assert m.success_count == 3  # 2 from f1, 1 from f2
    # Wilson 3/4 ≈ 0.30 (close to 0.30, not exact due to z=1.96 formula)
    assert 0.25 < m.confidence < 0.40


def test_swarm_same_id_dedup_passes_singletons_unchanged() -> None:
    """A Finding with a unique id passes through the dedup unchanged."""
    from agent_guardian.core.swarm import SwarmCommander
    from agent_guardian.models.csa import CsaCategory
    from agent_guardian.models.severity import Severity

    unique_id = _deterministic_finding_id("ASI01-GH-001", AsiCategory.ASI01)
    f = Finding(
        id=unique_id,
        probe_id="ASI01-GH-001",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0051"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success_count=1,
        success=True,
        confidence=0.207,
        verdict_v2="exploited",
        summary="goal-hijack-agent",
        created_at=datetime(2026, 6, 13, 12, 0, tzinfo=UTC),
        attempts=[_t(sequence=1, success=True, id="f-att200")],
    )
    cmd = SwarmCommander.__new__(SwarmCommander)
    result = cmd._dedupe_same_id_findings([f])
    assert result == [f]


# ---------------------------------------------------------------------------
# Phase 2 — LLM rollup helper
# ---------------------------------------------------------------------------


class _FakeEvalLLM:
    """Stub evaluator LLM that returns a canned string and records the prompt."""

    def __init__(self, response_text: str = "Operator-facing rollup of N attempts.") -> None:
        self.response_text = response_text
        self.last_prompt: str = ""
        self.call_count = 0

    async def complete(self, request):  # type: ignore[no-untyped-def]
        self.call_count += 1
        self.last_prompt = request.messages[0].content if request.messages else ""

        class _Resp:
            def __init__(self, text: str) -> None:
                self.text = text

        return _Resp(self.response_text)


class _RaisingEvalLLM:
    async def complete(self, request):  # type: ignore[no-untyped-def]
        raise RuntimeError("provider down")


async def test_synthesize_finding_summary_appends_corroboration_tail() -> None:
    """The framework must always append 'Reproduced in X of Y attempts.' tail,
    even if the LLM body forgets to mention it. This guarantees the
    operator sees the aggregate signal."""
    agent = _agent()
    fake = _FakeEvalLLM(response_text="Agent leaked customer PII.")
    agent.evaluator_llm = fake  # type: ignore[assignment]
    bucket = [
        _t(sequence=1, success=True),
        _t(sequence=2, success=True),
        _t(sequence=3, success=False, verdict_v2="vulnerable"),
    ]
    summary = await agent._synthesize_finding_summary(
        probe_id="ASI03-PII-001",
        asi=AsiCategory.ASI03,
        bucket=bucket,
        fallback="fallback",
    )
    assert summary == "Agent leaked customer PII. Reproduced in 2 of 3 attempts."
    assert fake.call_count == 1
    # Prompt must include the structured fields per the design §III.C contract.
    assert "Probe: ASI03-PII-001" in fake.last_prompt
    assert "ASI category: ASI03" in fake.last_prompt
    assert "Attempts: 2/3 succeeded" in fake.last_prompt


async def test_synthesize_finding_summary_falls_back_when_llm_raises() -> None:
    """An LLM error must not break aggregation — fall back to the rep
    Attempt's per-turn summary so no Finding is ever empty-summary."""
    agent = _agent()
    agent.evaluator_llm = _RaisingEvalLLM()  # type: ignore[assignment]
    bucket = [_t(sequence=1, success=True)]
    summary = await agent._synthesize_finding_summary(
        probe_id="ASI03-PII-001",
        asi=AsiCategory.ASI03,
        bucket=bucket,
        fallback="legacy per-turn summary",
    )
    assert summary == "legacy per-turn summary"


async def test_synthesize_finding_summary_deterministic_prompt_for_same_bucket() -> None:
    """The prompt construction must be byte-identical given the same bucket —
    a precondition for evaluator LLM reproducibility under temperature=0."""
    agent = _agent()
    fake_a = _FakeEvalLLM()
    fake_b = _FakeEvalLLM()
    bucket = [
        _t(sequence=1, success=True, verdict_v2="exploited"),
        _t(sequence=2, success=False, verdict_v2="vulnerable"),
    ]
    agent.evaluator_llm = fake_a  # type: ignore[assignment]
    await agent._synthesize_finding_summary(
        probe_id="ASI03-PII-001", asi=AsiCategory.ASI03, bucket=bucket, fallback=""
    )
    agent.evaluator_llm = fake_b  # type: ignore[assignment]
    await agent._synthesize_finding_summary(
        probe_id="ASI03-PII-001", asi=AsiCategory.ASI03, bucket=bucket, fallback=""
    )
    assert fake_a.last_prompt == fake_b.last_prompt
