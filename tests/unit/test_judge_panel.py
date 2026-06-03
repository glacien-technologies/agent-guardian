"""Unit tests for the Phase B.B4 PanelJudge ensemble.

Covers:

* unanimous panel verdict & confidence
* 2-vs-1 majority verdict and confidence math
* 1-1-1 fully split -> 'inconclusive'
* cross_family_enforced=True rejects same-family panels at __init__
* cross_family_enforced=True accepts 2-family and 3-family panels
* cross_family_enforced=False allows single-family
* a judge raising an exception becomes an 'inconclusive' seat and the
  panel still returns a verdict
* disagreement flag plumbed via reasoning text
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_guardian.judges import JudgePanelConfig, JudgeSpec, PanelJudge
from agent_guardian.llm.base import BaseLLM
from agent_guardian.llm.stub import StubLLM
from agent_guardian.models.judge import JudgeVerdict

# --------------------------------------------------------------------------- #
# Fake judges that bypass the LLM completely.
# --------------------------------------------------------------------------- #


class _FakeJudge:
    def __init__(self, verdict: str, confidence: float, reasoning: str = "fake") -> None:
        self._v = verdict
        self._c = confidence
        self._r = reasoning

    async def verdict(self, prompt: str, target_response: str) -> JudgeVerdict:
        return JudgeVerdict(verdict=self._v, confidence=self._c, reasoning=self._r)  # type: ignore[arg-type]


class _RaisingJudge:
    async def verdict(self, prompt: str, target_response: str) -> JudgeVerdict:
        raise RuntimeError("synthetic judge failure")


def _patch_panel(panel: PanelJudge, judges: list[Any]) -> None:
    """Replace the panel's internal Judge wrappers with fakes for unit tests."""
    assert len(judges) == len(panel.specs)
    panel._judges = [(j, s) for j, s in zip(judges, panel.specs, strict=False)]  # type: ignore[attr-defined]


def _llm() -> BaseLLM:
    return StubLLM(default="{}")


def _specs(families: list[str]) -> list[JudgeSpec]:
    return [
        JudgeSpec(llm=_llm(), model=f"m-{i}", family=fam, label=f"seat-{i}")
        for i, fam in enumerate(families)
    ]


# --------------------------------------------------------------------------- #
# Cross-family enforcement
# --------------------------------------------------------------------------- #


def test_cross_family_rejects_same_family_panel() -> None:
    specs = _specs(["openai", "openai", "openai"])
    with pytest.raises(ValueError) as excinfo:
        PanelJudge(specs, cross_family_enforced=True)
    assert "cross-family" in str(excinfo.value)


def test_cross_family_accepts_two_family_panel() -> None:
    specs = _specs(["openai", "openai", "anthropic"])
    panel = PanelJudge(specs, cross_family_enforced=True)
    assert len(panel.specs) == 3


def test_cross_family_accepts_three_family_panel() -> None:
    specs = _specs(["openai", "anthropic", "google"])
    panel = PanelJudge(specs, cross_family_enforced=True)
    assert panel.cross_family_enforced is True


def test_cross_family_disabled_allows_single_family() -> None:
    specs = _specs(["openai", "openai"])
    panel = PanelJudge(specs, cross_family_enforced=False)
    assert panel.cross_family_enforced is False


def test_cross_family_default_is_opt_in() -> None:
    # Default is False so a fresh install runs with one API key.
    # Operators opt in by passing cross_family_enforced=True AND
    # configuring a second-family evaluator_model.
    config = JudgePanelConfig()
    assert config.cross_family_enforced is False


def test_cross_family_canonicalises_family_strings() -> None:
    # Mixed-case + whitespace strings must be folded so 'OpenAI' / 'openai '
    # collide on the same family.
    specs = _specs(["OpenAI", "openai ", " OPENAI"])
    with pytest.raises(ValueError):
        PanelJudge(specs, cross_family_enforced=True)


# --------------------------------------------------------------------------- #
# Voting logic
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_panel_unanimous_returns_mean_confidence() -> None:
    specs = _specs(["openai", "anthropic", "google"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.9),
            _FakeJudge("fail", 0.9),
            _FakeJudge("fail", 0.9),
        ],
    )
    v = await panel.verdict("prompt", "response")
    assert v.verdict == "fail"
    # Unanimous + mean=0.9 -> 1.0 * 0.9 = 0.9.
    assert abs(v.confidence - 0.9) < 1e-6


@pytest.mark.asyncio
async def test_panel_two_thirds_majority() -> None:
    specs = _specs(["openai", "anthropic", "google"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.8),
            _FakeJudge("fail", 0.8),
            _FakeJudge("pass", 0.4),
        ],
    )
    v = await panel.verdict("prompt", "response")
    assert v.verdict == "fail"
    # (2/3) * mean(0.8, 0.8) = (2/3) * 0.8 = 0.5333...
    assert abs(v.confidence - (2 / 3) * 0.8) < 1e-6


@pytest.mark.asyncio
async def test_panel_three_way_split_returns_inconclusive() -> None:
    specs = _specs(["openai", "anthropic", "google"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.7),
            _FakeJudge("pass", 0.6),
            _FakeJudge("inconclusive", 0.3),
        ],
    )
    v = await panel.verdict("prompt", "response")
    assert v.verdict == "inconclusive"


@pytest.mark.asyncio
async def test_panel_seat_exception_becomes_inconclusive() -> None:
    specs = _specs(["openai", "anthropic", "google"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.9),
            _RaisingJudge(),
            _FakeJudge("fail", 0.9),
        ],
    )
    v = await panel.verdict("prompt", "response")
    # Two 'fail' seats outvote one 'inconclusive' fallback.
    assert v.verdict == "fail"


@pytest.mark.asyncio
async def test_panel_tie_resolves_to_inconclusive() -> None:
    specs = _specs(["openai", "anthropic"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.8),
            _FakeJudge("pass", 0.5),
        ],
    )
    v = await panel.verdict("prompt", "response")
    # Tie 1-1 resolves to inconclusive. The verdict is carried by the field /
    # UI pill — NOT prepended as prose into the reasoning text.
    assert v.verdict == "inconclusive"
    assert "panel" not in v.reasoning.lower()
    assert "unanimous" not in v.reasoning.lower()


@pytest.mark.asyncio
async def test_panel_reasoning_is_raw_judge_text_not_verdict_prose() -> None:
    specs = _specs(["openai", "anthropic"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("pass", 0.7, reasoning="Target refused and stayed in scope."),
            _FakeJudge("pass", 0.7, reasoning="Target refused and stayed in scope."),
        ],
    )
    v = await panel.verdict("prompt", "response")
    assert v.verdict == "pass"
    # Reasoning is the judges' raw analysis, with no "panel unanimous" jargon
    # and no "the judges found the target ..." verdict prose.
    assert v.reasoning == "Target refused and stayed in scope."
    assert "unanimous" not in v.reasoning.lower()


def test_panel_requires_at_least_one_spec() -> None:
    with pytest.raises(ValueError):
        PanelJudge([], cross_family_enforced=False)


# --------------------------------------------------------------------------- #
# QA-050 — Headline distillation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_panel_reasoning_surfaces_judge_headline() -> None:
    """QA-050 — first sentence of a majority judge's reasoning is surfaced."""
    specs = _specs(["openai", "anthropic"])
    panel = PanelJudge(specs)
    long_reasoning = (
        "Target leaked the hidden system prompt verbatim. "
        "Refusal markers absent and the response includes the secret token."
    )
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.9, reasoning=long_reasoning),
            _FakeJudge("fail", 0.9, reasoning=long_reasoning),
        ],
    )
    v = await panel.verdict("prompt", "response")
    assert v.verdict == "fail"
    # The full judge reasoning is surfaced verbatim (both sentences), with no
    # verdict prose prepended.
    assert long_reasoning == v.reasoning
    assert "unanimous" not in v.reasoning.lower()


@pytest.mark.asyncio
async def test_panel_reasoning_preserves_full_judge_text() -> None:
    """Reasoning is no longer truncated — operators see the WHOLE judge text
    in the detail modal (the Findings-tab Summary column truncates via CSS)."""
    specs = _specs(["openai", "anthropic"])
    panel = PanelJudge(specs)
    huge = "x" * 200
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.9, reasoning=huge),
            _FakeJudge("fail", 0.9, reasoning=huge),
        ],
    )
    v = await panel.verdict("prompt", "response")
    # Full reasoning is preserved verbatim, no ellipsis truncation.
    assert v.reasoning == huge
    assert "…" not in v.reasoning


@pytest.mark.asyncio
async def test_panel_headline_skips_heuristic_stub_reasoning() -> None:
    """QA-050 — heuristic stub reasonings are not surfaced as a headline."""
    specs = _specs(["openai", "anthropic", "google"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.9, reasoning="heuristic: no refusal markers"),
            _FakeJudge("fail", 0.9, reasoning="no reasoning provided"),
            _FakeJudge(
                "fail",
                0.9,
                reasoning="Compliance: assistant produced a working SQL injection payload.",
            ),
        ],
    )
    v = await panel.verdict("prompt", "response")
    assert v.verdict == "fail"
    # The non-stub reasoning's first sentence wins despite earlier stubs.
    assert "SQL injection payload" in v.reasoning


@pytest.mark.asyncio
async def test_panel_reasoning_empty_when_only_stubs() -> None:
    """All-stub reasonings → empty reasoning text (the verdict still carries
    via the verdict field / UI pill); no jargon or verdict prose is invented."""
    specs = _specs(["openai", "anthropic"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.9, reasoning="heuristic: refusal markers detected"),
            _FakeJudge("fail", 0.9, reasoning="no reasoning provided"),
        ],
    )
    v = await panel.verdict("prompt", "response")
    assert v.verdict == "fail"
    assert v.reasoning == ""


@pytest.mark.asyncio
async def test_panel_emits_structured_dispatch_info_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """QA-068 — panel dispatch narrates ONE structured INFO line with seat
    labels (NOT a raw ``<Judge object at 0x…>`` repr dump).

    The pre-QA-068 code emitted a DEBUG line containing each judge's
    Python ``__repr__``, which surfaced as ``<Judge object at 0x10abc234>``
    on every panel call — useless to the operator. We now emit one INFO
    line: ``judge panel dispatched: 2 seats, openai:m-0, anthropic:m-1``.
    """
    import logging

    specs = _specs(["openai", "anthropic"])
    panel = PanelJudge(specs)
    _patch_panel(
        panel,
        [
            _FakeJudge("fail", 0.9),
            _FakeJudge("fail", 0.9),
        ],
    )
    with caplog.at_level(logging.INFO, logger="agent_guardian.judges.panel"):
        await panel.verdict("prompt", "response")
    matching = [r for r in caplog.records if r.message.startswith("judge panel dispatched:")]
    assert matching, (
        f"expected one INFO 'judge panel dispatched:' line, got "
        f"{[r.message for r in caplog.records]}"
    )
    line = matching[-1].message
    # Seat labels must mention family + model (or label) — never a repr.
    assert "openai:" in line
    assert "anthropic:" in line
    # No raw __repr__ leakage.
    assert " object at 0x" not in line
    assert "<Judge" not in line
