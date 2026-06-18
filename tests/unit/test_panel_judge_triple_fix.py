"""rc37 deep-review HIGH-3/4/5 — PanelJudge triple-fix.

Three related PanelJudge defects identified in the rc37 forensic matrix
review. Fixed together because they share the same subsystem and the
same observability surface.

#3 (closes #231 panel-determinism slice) — every seat received the same
    seed in rc37 (34/34 sampled calls at seed=42). The constructor stored
    ``base_seed`` correctly and the dispatch helper computed ``base + idx``,
    but the empirical evidence proves the seat-index offset was not
    actually distinct across the 3 seats. The invariant: same scan seed
    AND distinct per-seat seeds. ``len(set(seeds_observed)) == n_judges``.

#4 (closes #250) — ``min_judges=3`` padded a 2-spec same-family panel by
    cloning seat[0] under a new label, producing a same-LLM same-prompt
    same-family third seat. 35/35 sampled panels unanimous → the
    variance-reduction value of an L2 third seat is forfeited at 3x the
    cost. Fix: pad to ``min_judges`` only when a HETEROGENEOUS-family
    spec is available among the existing specs; otherwise keep the
    seat list at ``len(specs)`` (no same-family clone). The shipped
    SwarmCommander default drops to ``min_judges=2`` so the on-disk
    behaviour matches what's documented and pays only for variance-
    reducing seats.

#5 (closes #251) — only "judge panel dispatched: N seats" reached
    events.jsonl (INFO). The richer ``panel verdicts collected`` /
    ``panel majority`` / ``panel seat raised`` lines stayed at DEBUG, so
    downstream tooling could not tell a 3-0 from a 2-1 majority. Fix:
    PanelJudge accepts an ``event_emitter`` callback; the SwarmCommander
    wires it to a ``SwarmEvent(kind='panel_verdict', payload=...)``
    emission so events.jsonl carries the full vote shape. The verdict
    object also carries a ``panel`` sidecar so the per-finding payload
    in report.json mirrors the panel outcome.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_guardian.judges.panel import JudgeSpec, PanelJudge
from agent_guardian.models.judge import JudgeVerdict


def _make_spec(family: str, label: str) -> JudgeSpec:
    llm = MagicMock()
    return JudgeSpec(llm=llm, model=f"{family}:{label}-model", family=family, label=label)


def _stub_verdict(v: str = "defended", c: float = 1.0) -> JudgeVerdict:
    return JudgeVerdict(
        verdict=v,  # type: ignore[arg-type]
        reasoning="(stub)",
        confidence=c,
        refused=False,
        observable_compromise=False,
        evaluator_attack=False,
        followup_probe="",
        evidence="",
    )


def _patch_seats(panel: PanelJudge, return_verdicts: list[JudgeVerdict]) -> list[AsyncMock]:
    """Replace each seat's inner Judge with an AsyncMock that records the
    seed kwarg passed at dispatch and returns a fixed verdict per seat."""
    mocks: list[AsyncMock] = []
    new_judges: list[tuple[AsyncMock, JudgeSpec]] = []
    for (_judge_obj, spec), rv in zip(panel._judges, return_verdicts, strict=True):
        mock = AsyncMock()
        mock.verdict = AsyncMock(return_value=rv)
        mocks.append(mock)
        new_judges.append((mock, spec))
    panel._judges = new_judges  # type: ignore[assignment]
    return mocks


# ----------------------------------------------------------------------- #
# DEFECT #3 — seat-index seed offset across N seats (including N=3 pad).
# ----------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_panel_dispatches_distinct_seeds_across_all_seats() -> None:
    """``len(set(seeds_observed)) == n_judges`` — the smoke-test invariant
    called out in the rc37 review. Three-seat panel, base_seed=42 → seats
    receive {42, 43, 44}. Reruns at the same base_seed reproduce the same
    per-seat seeds (determinism), while no two seats share a seed
    (decorrelated draws).

    Uses cross-family specs so the heterogeneous-pad path applies and the
    panel actually carries 3 seats.
    """
    specs = [
        _make_spec("gemini", "attacker-as-judge"),
        _make_spec("openai", "evaluator-as-judge"),
    ]
    panel = PanelJudge(specs=specs, min_judges=3, seed=42)
    # The constructor must have padded to 3 because seat[0] family != seat[1]
    # family (gemini, openai) — a third spec is added (any of the two
    # families is acceptable, but a third seat must exist).
    assert len(panel.specs) == 3, (
        f"panel built {len(panel.specs)} seats; expected 3 (heterogeneous pad)"
    )

    mocks = _patch_seats(panel, [_stub_verdict() for _ in panel._judges])
    await panel.verdict(prompt="probe", target_response="response")

    seeds_observed = [mock.verdict.await_args.kwargs.get("seed") for mock in mocks]
    assert len(set(seeds_observed)) == len(mocks), (
        f"seat seeds collided: {seeds_observed} — base_seed + seat_index must "
        f"produce N distinct seeds across N seats (rc37 HIGH-3 invariant)"
    )
    # Same-seed reproducibility: re-run with a freshly mocked panel returns
    # the same per-seat seed set when base_seed is held constant.
    panel2 = PanelJudge(specs=specs, min_judges=3, seed=42)
    mocks2 = _patch_seats(panel2, [_stub_verdict() for _ in panel2._judges])
    await panel2.verdict(prompt="probe", target_response="response")
    seeds_rerun = [mock.verdict.await_args.kwargs.get("seed") for mock in mocks2]
    assert sorted(seeds_observed) == sorted(seeds_rerun), (
        f"reproducibility broken: first={seeds_observed} second={seeds_rerun}"
    )


# ----------------------------------------------------------------------- #
# DEFECT #4 — heterogeneous-pad gating.
# ----------------------------------------------------------------------- #


def test_panel_does_not_pad_with_same_family_clone() -> None:
    """A 2-spec same-family panel with min_judges=3 must NOT grow to 3 by
    cloning seat[0]. The third seat would vote with the same LLM at the
    same prompt — correlated draws, paying 3x the cost for zero new
    variance signal. Keep the seat count at len(specs).

    This pins the rc37 HIGH-4 structural fix.
    """
    specs = [
        _make_spec("gemini", "attacker-as-judge"),
        _make_spec("gemini", "evaluator-as-judge"),
    ]
    panel = PanelJudge(specs=specs, min_judges=3)
    assert len(panel.specs) == 2, (
        f"panel padded to {len(panel.specs)} seats with same-family clone; "
        f"this defeats variance-reduction (35/35 sampled panels unanimous "
        f"in rc37). Must keep at 2 when no heterogeneous pad is available."
    )


def test_panel_pads_with_heterogeneous_family_when_available() -> None:
    """When the existing specs already span >=2 distinct families, padding
    can add a third seat by re-seating one of the heterogeneous specs. The
    third seat carries a distinct family from at least one of the originals
    so panel-level family diversity strictly increases (or holds; never
    drops below the originals)."""
    specs = [
        _make_spec("gemini", "attacker-as-judge"),
        _make_spec("openai", "evaluator-as-judge"),
    ]
    panel = PanelJudge(specs=specs, min_judges=3)
    assert len(panel.specs) == 3
    families = sorted({s.canonical_family for s in panel.specs})
    # Two distinct families are preserved across the 3 seats.
    assert set(families) == {"gemini", "openai"}, (
        f"heterogeneous pad lost family diversity: {families}"
    )


def test_panel_min_judges_default_is_two() -> None:
    """``JudgePanelConfig.min_judges`` default is 2 (was 3 in rc37). The
    3-seat L2 escalation is reachable only when a heterogeneous pad is
    available; same-family same-prompt clones don't reduce variance, so
    they are not paid for."""
    from agent_guardian.judges.panel import JudgePanelConfig

    cfg = JudgePanelConfig()
    assert cfg.min_judges == 2, (
        f"JudgePanelConfig.min_judges default is {cfg.min_judges}; expected 2 "
        f"so the shipped panel does not pay for a same-family clone seat "
        f"(rc37 HIGH-4)."
    )


# ----------------------------------------------------------------------- #
# DEFECT #5 — panel_verdict event + per-finding payload.
# ----------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_panel_emits_panel_verdict_event_with_full_vote_shape() -> None:
    """An ``event_emitter`` callback fires exactly once per ``verdict()``
    call with the full vote shape: seat_verdicts (per-seat string),
    seat_confidences (per-seat float), agreement_fraction (float in [0,1]),
    majority (string), confidence (float). The shape is what downstream
    tooling needs to distinguish a 3-0 from a 2-1 outcome.

    Issue #259 — when seats 1 and 2 dissent, the panel now escalates to
    a 3rd seat at runtime. This test uses unanimous high-confidence
    verdicts so the L2 escalation does NOT fire and the emitted payload
    carries exactly the 2 seats it was patched with (the panel-emission
    contract is independent of the dissent-escalation contract)."""
    specs = [
        _make_spec("gemini", "attacker-as-judge"),
        _make_spec("openai", "evaluator-as-judge"),
    ]
    captured: list[dict[str, Any]] = []
    panel = PanelJudge(
        specs=specs,
        seed=42,
        event_emitter=lambda payload: captured.append(payload),
    )
    # Unanimous high-confidence vote: no L2 escalation fires, so the
    # emitted payload carries exactly the 2 seats patched in.
    _patch_seats(
        panel,
        [
            _stub_verdict("defended", 0.9),
            _stub_verdict("defended", 0.7),
        ],
    )
    final = await panel.verdict(prompt="probe", target_response="response")

    assert len(captured) == 1, (
        f"expected exactly one panel_verdict emission per verdict() call; got {len(captured)}"
    )
    payload = captured[0]
    # The vote shape contract.
    for key in (
        "seat_verdicts",
        "seat_confidences",
        "agreement_fraction",
        "majority",
        "confidence",
    ):
        assert key in payload, f"panel_verdict payload missing key {key!r}: {payload}"

    assert payload["seat_verdicts"] == ["defended", "defended"]
    assert payload["seat_confidences"] == [0.9, 0.7]
    assert payload["majority"] == final.verdict
    assert 0.0 <= payload["agreement_fraction"] <= 1.0
    assert 0.0 <= payload["confidence"] <= 1.0


@pytest.mark.asyncio
async def test_panel_verdict_carries_panel_sidecar_for_report_json() -> None:
    """The returned JudgeVerdict carries a ``panel`` sidecar dict so the
    per-finding payload in report.json can mirror the vote shape. This
    closes the rc37 HIGH-5 gap where the report could not show a 3-0
    vs 2-1 panel outcome.

    The sidecar mirrors the events.jsonl payload exactly so downstream
    consumers don't branch on the source."""
    specs = [
        _make_spec("gemini", "attacker-as-judge"),
        _make_spec("openai", "evaluator-as-judge"),
    ]
    panel = PanelJudge(specs=specs, seed=42)
    _patch_seats(
        panel,
        [
            _stub_verdict("exploited", 0.9),
            _stub_verdict("exploited", 0.8),
        ],
    )
    final = await panel.verdict(prompt="probe", target_response="response")
    assert final.panel is not None, (
        "JudgeVerdict.panel sidecar missing — report.json cannot mirror "
        "the panel vote shape per-finding (rc37 HIGH-5)."
    )
    assert final.panel["majority"] == "exploited"
    assert final.panel["seat_verdicts"] == ["exploited", "exploited"]
    assert final.panel["agreement_fraction"] == 1.0


def test_finding_carries_panel_payload_through_to_report_json() -> None:
    """The ``Finding`` model carries an optional ``panel`` dict so the
    per-finding panel payload survives serialization into report.json.
    Without this field the sidecar would be silently dropped (Finding's
    ``extra='ignore'`` model config)."""
    from datetime import UTC, datetime

    from agent_guardian.models.asi import AsiCategory
    from agent_guardian.models.csa import CsaCategory
    from agent_guardian.models.finding import Finding
    from agent_guardian.models.severity import Severity

    panel_payload = {
        "seat_verdicts": ["exploited", "exploited", "defended"],
        "seat_confidences": [0.9, 0.8, 0.6],
        "agreement_fraction": 2 / 3,
        "majority": "exploited",
        "confidence": 0.566,
    }
    finding = Finding(
        id="f-test",
        probe_id="probe-1",
        asi=AsiCategory.ASI01,
        mitre_atlas=["AML.T0051"],
        csa_category=CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
        severity=Severity.HIGH,
        attempt_count=1,
        success=True,
        confidence=0.566,
        summary="seat-2/3 majority exploited",
        created_at=datetime.now(tz=UTC),
        panel=panel_payload,
    )
    # Round-trip: serialized JSON includes the panel key.
    serialized = finding.model_dump()
    assert serialized["panel"] == panel_payload, (
        "Finding.panel did not round-trip through model_dump() — report.json "
        "will lose the panel vote shape on serialization."
    )
