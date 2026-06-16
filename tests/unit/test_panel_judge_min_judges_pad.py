"""Issue #229 + rc37 HIGH-4 (#250) — heterogeneous-only PanelJudge padding.

PR #187 advertised an L2 escalation that promotes the judge panel to a
3-seat majority vote on HIGH/CRITICAL severity verdicts. PR #240 (rc37)
shipped padding to ``min_judges=3`` by cloning seat[0]; the rc37 deep-
review found 35/35 sampled panels unanimous because the third seat ran
the same LLM at the same prompt: correlated draws, zero new variance
signal, at 3x the panel cost.

The current contract (rc38): PanelJudge pads to ``min_judges`` only
when the existing specs ALREADY span >=2 distinct families. Same-family
clones are never paid for — when there is no heterogeneous pad
available the seat list stays at ``len(specs)``.

This test pins:

1. Cross-family padding works (heterogeneous specs grow to min_judges).
2. Pad seats are labelled distinctly (so log/audit can tell them
   apart from the originals).
3. Padding never raises; if too few specs are passed and no
   heterogeneous pad is available, the panel stays at ``len(specs)``.
4. Setting ``min_judges <= len(specs)`` is a no-op (no over-padding).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from agent_guardian.judges.panel import JudgeSpec, PanelJudge


def _make_spec(family: str, label: str) -> JudgeSpec:
    llm = MagicMock()
    return JudgeSpec(llm=llm, model=f"{family}:{label}-model", family=family, label=label)


def test_panel_pads_to_min_judges_only_when_heterogeneous_available() -> None:
    """Heterogeneous specs (gemini + openai) with min_judges=3 grow to 3
    seats so the L2 escalation actually fires with a cross-family panel.

    Pinned shape: the third seat re-seats one of the originals, so
    family diversity is preserved across the now-3 seats and dissent on
    the existing family lines remains a real signal."""
    specs = [_make_spec("gemini", "attacker-as-judge"), _make_spec("openai", "evaluator-as-judge")]
    panel = PanelJudge(specs=specs, min_judges=3)

    assert len(panel.specs) == 3
    families = sorted({s.canonical_family for s in panel.specs})
    assert set(families) == {"gemini", "openai"}, (
        f"heterogeneous pad lost family diversity: {families}"
    )


def test_panel_pad_seats_have_distinct_labels() -> None:
    """Pad seats must be distinguishable in logs / audit / debug output
    so an operator can tell the 3rd vote was a re-seated pad and not a
    real new judge family. Requires the heterogeneous-pad path so a
    third seat actually exists."""
    specs = [_make_spec("gemini", "attacker-as-judge"), _make_spec("openai", "evaluator-as-judge")]
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


def test_panel_single_spec_does_not_pad_with_same_family_clone() -> None:
    """rc37 HIGH-4 — a single-spec panel with min_judges=3 must NOT pad
    by cloning the single spec. Cloning a same-LLM same-prompt seat
    produces correlated draws (35/35 unanimous in the rc37 matrix) for
    zero new variance signal. The seat list stays at len(specs)."""
    specs = [_make_spec("gemini", "only-judge")]
    panel = PanelJudge(specs=specs, min_judges=3)
    assert len(panel.specs) == 1, (
        f"single-spec panel padded to {len(panel.specs)} via same-family clone; "
        f"rc37 HIGH-4 forbids same-family pads."
    )
