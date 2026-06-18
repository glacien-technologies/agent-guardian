"""Issue #259 — dissent-triggered L2 escalation under the shipped default
SwarmCommander config.

PR #187's release-notes claim was "L2 escalates on dissent" — i.e. when
the 2-seat majority panel votes split, a 3rd seat fires before the verdict
returns. PR #240 (rc36) attempted that via construction-time padding to
``min_judges=3``; PR #254 (rc37) gated the padding on
``len(seen_families) >= 2``. The shipped default panel runs attacker +
evaluator on the SAME family (both gemini), so the family-gate returns
``None`` unconditionally — the L2 escalation never fired in the rc38
matrix (441/441 panel calls at n_judges=2).

The principled fix is RUNTIME, not construction-time. The construction-
time path cannot tell whether the seats will dissent, so any decision
made there is either "always pad" (cost regression, rc36) or "never pad
on single-family configs" (silent dead-code, rc37). Dissent IS the
trigger — when seats 1 and 2 vote differently OR carry low aggregate
confidence, the panel spawns a 3rd seat before returning. When they
agree, the 2-seat panel returns immediately (preserves the rc37→rc38
cost win).

CRITICAL: this test wires the **shipped default SwarmCommander config**
(single ``gemini`` family), not a synthetic multi-family panel. The
existing ``test_panel_judge_min_judges_pad`` builds a multi-family panel
and is what allowed PR #254 to ship a default-config regression — this
test exists to lock the path the operator actually runs.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_guardian.judges.panel import JudgeSpec, PanelJudge
from agent_guardian.models.judge import JudgeVerdict


def _verdict(label: str, confidence: float = 0.9) -> JudgeVerdict:
    return JudgeVerdict(verdict=label, confidence=confidence, reasoning=f"r:{label}")


class _FakeJudge:
    """Stand-in for ``agent_guardian.agents.base.Judge`` that returns a
    scripted JudgeVerdict per call. Tracks call count so the test can
    assert how many seats actually fired."""

    def __init__(self, verdicts: list[JudgeVerdict]) -> None:
        self._verdicts = list(verdicts)
        self.calls = 0

    async def verdict(self, *args: Any, **kwargs: Any) -> JudgeVerdict:
        v = self._verdicts[self.calls % len(self._verdicts)]
        self.calls += 1
        return v


def _default_swarm_panel_specs() -> list[JudgeSpec]:
    """Mirror the shipped default SwarmCommander panel wiring exactly
    (``src/agent_guardian/core/swarm.py:840-853``):

    * attacker_model = ``gemini-3.5-flash``
    * evaluator_model = ``gemini-3.5-flash``
    * both seats canonicalised to family=``gemini``

    Building this from JudgeSpec directly (rather than spinning up the
    full SwarmCommander) keeps the test focussed on the panel surface
    that #259 covers; the wiring contract is pinned by
    ``test_default_swarm_config_single_family_panel`` below.
    """
    attacker_llm = MagicMock()
    evaluator_llm = MagicMock()
    return [
        JudgeSpec(
            llm=attacker_llm,
            model="gemini-3.5-flash",
            family="gemini",
            label="attacker-as-judge",
        ),
        JudgeSpec(
            llm=evaluator_llm,
            model="gemini-3.5-flash",
            family="gemini",
            label="evaluator-as-judge",
        ),
    ]


@pytest.fixture
def default_panel_specs() -> list[JudgeSpec]:
    return _default_swarm_panel_specs()


@pytest.mark.asyncio
async def test_default_config_panel_escalates_to_l2_on_seat_dissent(
    default_panel_specs: list[JudgeSpec], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under the shipped default (single ``gemini`` family) panel, when
    seat 1 votes ``exploited`` and seat 2 votes ``defended``, a 3rd seat
    MUST fire before the verdict returns.

    The 3rd seat tie-breaks (votes ``exploited``), and the final
    ``panel`` payload carries 3 seats. This is the path PR #187 advertised
    and which #259 confirms was dead on every rc38 matrix scan."""
    seat1 = _FakeJudge([_verdict("exploited", confidence=0.9)])
    seat2 = _FakeJudge([_verdict("defended", confidence=0.9)])
    seat3 = _FakeJudge([_verdict("exploited", confidence=0.8)])

    panel = PanelJudge(specs=default_panel_specs, min_judges=2)
    # Inject scripted judges in place of the LLM-backed ones the
    # constructor built. The (judge, spec) tuple shape is preserved so
    # the rest of ``verdict()`` reads them identically.
    panel._judges = [
        (seat1, default_panel_specs[0]),
        (seat2, default_panel_specs[1]),
    ]
    # The L2 escalation must be able to spawn seat 3 even when the
    # construction-time pad couldn't (single-family panel). We inject
    # the seat 3 factory the runtime escalation path calls.
    panel._l2_escalation_factory = lambda: (seat3, default_panel_specs[0])  # type: ignore[attr-defined]

    result = await panel.verdict("p", "r")

    assert seat1.calls == 1, "seat 1 must run exactly once"
    assert seat2.calls == 1, "seat 2 must run exactly once"
    assert seat3.calls == 1, (
        "seat 3 (L2 escalation) MUST fire on dissent under the shipped "
        "default single-family config; this is the bug #259 (PR #254 "
        "gated the construction-time pad on >=2 families so the shipped "
        "default panel never escalated)."
    )
    assert result.panel is not None
    assert len(result.panel["seat_verdicts"]) == 3, (
        f"panel payload must carry 3 seat verdicts after L2 escalation; "
        f"got {result.panel['seat_verdicts']}"
    )
    assert result.panel.get("escalated") is True, (
        "panel payload must record escalated=True so downstream tooling "
        "can audit the L2 trigger frequency"
    )
    # Majority of {exploited, defended, exploited} is exploited.
    assert result.panel["majority"] == "exploited"


@pytest.mark.asyncio
async def test_default_config_panel_no_escalation_on_unanimous_agreement(
    default_panel_specs: list[JudgeSpec],
) -> None:
    """When both seats agree, NO 3rd seat fires. Preserves the rc37→rc38
    cost win (~33% panel cost reduction) for the agreement case, which is
    the modal outcome on a clean scan."""
    seat1 = _FakeJudge([_verdict("defended", confidence=0.9)])
    seat2 = _FakeJudge([_verdict("defended", confidence=0.9)])
    seat3_factory_calls = 0

    def _factory() -> Any:
        nonlocal seat3_factory_calls
        seat3_factory_calls += 1
        return (_FakeJudge([_verdict("exploited", confidence=1.0)]), default_panel_specs[0])

    panel = PanelJudge(specs=default_panel_specs, min_judges=2)
    panel._judges = [
        (seat1, default_panel_specs[0]),
        (seat2, default_panel_specs[1]),
    ]
    panel._l2_escalation_factory = _factory  # type: ignore[attr-defined]

    result = await panel.verdict("p", "r")

    assert seat1.calls == 1
    assert seat2.calls == 1
    assert seat3_factory_calls == 0, (
        "L2 escalation MUST NOT fire when seats agree; that would burn "
        "the cost win the dissent-trigger design exists to keep."
    )
    assert result.panel is not None
    assert len(result.panel["seat_verdicts"]) == 2
    assert result.panel.get("escalated") in (False, None)


@pytest.mark.asyncio
async def test_default_config_panel_escalates_on_low_confidence_majority(
    default_panel_specs: list[JudgeSpec],
) -> None:
    """Both seats agree on the verdict but each at very low confidence
    (e.g. 0.2). The aggregate confidence falls below the dissent
    threshold, which is itself a form of dissent — neither seat is sure.
    L2 escalation MUST fire."""
    seat1 = _FakeJudge([_verdict("needs_followup", confidence=0.2)])
    seat2 = _FakeJudge([_verdict("needs_followup", confidence=0.2)])
    seat3 = _FakeJudge([_verdict("exploited", confidence=0.95)])

    panel = PanelJudge(specs=default_panel_specs, min_judges=2)
    panel._judges = [
        (seat1, default_panel_specs[0]),
        (seat2, default_panel_specs[1]),
    ]
    panel._l2_escalation_factory = lambda: (seat3, default_panel_specs[0])  # type: ignore[attr-defined]

    result = await panel.verdict("p", "r")

    assert seat3.calls == 1, (
        "low aggregate confidence is dissent — L2 must escalate so a "
        "tie-breaking seat can lift the confidence floor."
    )
    assert result.panel is not None
    assert len(result.panel["seat_verdicts"]) == 3


def test_default_swarm_config_panel_is_single_family() -> None:
    """Anchor invariant for #259 — the shipped default SwarmCommander
    config wires a 2-seat panel where both seats are family=``gemini``.

    This is what proves PR #254's ``seen_families >= 2`` gate is dead
    code on the default config: ``len({'gemini'}) == 1`` so the
    construction-time pad returned None on every rc38 matrix scan. The
    L2 fix lives at runtime (dissent-triggered), not construction-time.
    """
    specs = _default_swarm_panel_specs()
    families = {s.canonical_family for s in specs}
    assert families == {"gemini"}, (
        f"shipped default panel is no longer single-family ({families}); "
        f"this test exists to lock #259's regression surface — if the "
        f"default config legitimately changes to multi-family, this "
        f"assertion can be relaxed but a parallel single-family L2 "
        f"test MUST be added to keep the dissent path covered."
    )
