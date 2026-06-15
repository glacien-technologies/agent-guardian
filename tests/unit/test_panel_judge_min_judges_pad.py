"""Issue #229 — PanelJudge L2 escalation never fires.

PR #187 advertised an L2 escalation that promotes the judge panel to a
3-seat majority vote on HIGH/CRITICAL severity verdicts. The rc35 deep-
review found the escalation never fires: 986 of 986 panel calls run at
``n_judges=2`` because the panel is hard-coded to a 2-seat construction
and ``JudgePanelConfig.min_judges`` (default 3) is declared but never
read. The L2 fallback in ``AsiAgent.run()`` is explicitly bypassed when
a panel is present.

The fix: respect ``min_judges``. When ``len(specs) < min_judges``,
PanelJudge pads its seat list by appending re-seated copies of the
existing seats with distinct labels (so each pad fires as a separate
judge call). The default config now constructs a 3-seat panel (the
2 distinct family seats + a re-vote pad), matching PR #187's intent.

This test pins:

1. ``PanelJudge(min_judges=N)`` produces ``>= N`` seats.
2. Pad seats are labelled distinctly (so log/audit can tell them
   apart from the originals).
3. Padding never raises; if too few specs are passed, we pad up.
4. Setting ``min_judges <= len(specs)`` is a no-op (no over-padding).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from agent_guardian.judges.panel import JudgeSpec, PanelJudge


def _make_spec(family: str, label: str) -> JudgeSpec:
    llm = MagicMock()
    return JudgeSpec(llm=llm, model=f"{family}:{label}-model", family=family, label=label)


def test_panel_pads_to_min_judges_when_specs_undershoot() -> None:
    """The default config passes 2 specs but min_judges=3. Panel must
    pad to 3 seats so the L2 escalation actually fires."""
    specs = [_make_spec("gemini", "attacker-as-judge"), _make_spec("gemini", "evaluator-as-judge")]
    panel = PanelJudge(specs=specs, min_judges=3)

    assert len(panel.specs) >= 3, (
        f"PanelJudge did not pad to min_judges=3; got {len(panel.specs)} seats. "
        f"PR #187's L2 escalation requires >=3 seats on HIGH/CRITICAL verdicts; "
        f"otherwise n_judges stays at 2 across every scan (#229)."
    )


def test_panel_pad_seats_have_distinct_labels() -> None:
    """Pad seats must be distinguishable in logs / audit / debug output
    so an operator can tell the 3rd vote was a re-seated pad and not a
    real new judge family."""
    specs = [_make_spec("gemini", "attacker-as-judge"), _make_spec("gemini", "evaluator-as-judge")]
    panel = PanelJudge(specs=specs, min_judges=3)

    labels = [s.label for s in panel.specs]
    assert len(set(labels)) == len(labels), (
        f"PanelJudge pad seats have duplicate labels: {labels}. Each seat "
        f"must be uniquely labelled so the panel dispatch log shows three "
        f"distinct dispatch lines and audit can attribute each verdict."
    )


def test_panel_min_judges_default_is_back_compat() -> None:
    """A panel constructed without an explicit ``min_judges`` MUST NOT
    silently grow beyond the caller's specs. Back-compat for any caller
    that constructed a 2-seat panel pre-fix."""
    specs = [_make_spec("gemini", "a"), _make_spec("openai", "b")]
    panel = PanelJudge(specs=specs)  # no min_judges arg
    assert len(panel.specs) == 2, (
        "PanelJudge with no min_judges argument grew beyond the caller's "
        "specs; default must be back-compat (no padding) so callers that "
        "intentionally configured a 2-seat panel still get exactly 2 seats."
    )


def test_panel_min_judges_le_specs_is_noop() -> None:
    """If min_judges <= len(specs), don't over-pad — the caller already
    provided enough seats."""
    specs = [_make_spec("gemini", "a"), _make_spec("openai", "b"), _make_spec("anthropic", "c")]
    panel = PanelJudge(specs=specs, min_judges=3)
    assert len(panel.specs) == 3


def test_panel_min_judges_one_specs_pads_to_three() -> None:
    """Edge case: a single-spec panel with min_judges=3 should pad to
    3 (the L2 single-judge N-vote pattern)."""
    specs = [_make_spec("gemini", "only-judge")]
    panel = PanelJudge(specs=specs, min_judges=3)
    assert len(panel.specs) >= 3
