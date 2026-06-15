"""Issue #227 — --seed not threaded to judge panel.

The rc35 deep-review A5 finding: ``--seed`` propagates to attacker calls
(verifiable in memory.jsonl) but not to judge calls. Consensus stability
on the rc35 panel was already 99% (975/985 panels unanimous at confidence
1.00), so the impact is small — but on the 1% dissent cases reproducibility
is non-deterministic, which breaks the determinism contract PR #195 / #187
worked to establish.

The fix: ``PanelJudge`` accepts ``seed`` in its constructor; each seat's
``Judge.verdict`` call receives ``seed + seat_index`` so same-seed reruns
reproduce per-seat verdicts (full panel reproducibility) while the
per-seat offset avoids 3 identical samples that would defeat the
variance-reduction purpose of L2 (PR #229's 3-vote pad pattern).

The SwarmCommander passes ``config.seed`` to the PanelJudge so the
shipped default opts in. Providers that ignore ``seed`` (Anthropic /
Bedrock) silently no-op -- this is the same behaviour ``Judge.verdict``
already documents.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_guardian.judges.panel import JudgeSpec, PanelJudge


def _make_spec(family: str, label: str) -> JudgeSpec:
    """Build a JudgeSpec with a mock LLM. Pre-baking the LLM mock here
    keeps the test focused on seed wiring (we don't need real verdict
    semantics)."""
    llm = MagicMock()
    return JudgeSpec(llm=llm, model=f"{family}:{label}-model", family=family, label=label)


@pytest.mark.asyncio
async def test_panel_judge_constructor_accepts_seed_keyword() -> None:
    """Locks the constructor surface. A future refactor that drops
    ``seed`` from the signature would silently regress reproducibility
    on the 1% panel dissent cases."""
    specs = [_make_spec("gemini", "a"), _make_spec("gemini", "b")]
    panel = PanelJudge(specs=specs, seed=42)
    # No exception means the kwarg is accepted; assert the panel is
    # constructible at all.
    assert len(panel.specs) == 2


@pytest.mark.asyncio
async def test_panel_judge_seed_defaults_to_none() -> None:
    """Strict back-compat: a caller that omits ``seed`` still gets a
    working panel. The downstream call passes ``seed=None`` to each
    Judge.verdict (which then silently no-ops on the provider)."""
    specs = [_make_spec("gemini", "a"), _make_spec("gemini", "b")]
    # No exception -> back-compat preserved.
    panel = PanelJudge(specs=specs)
    assert len(panel.specs) == 2


@pytest.mark.asyncio
async def test_panel_judge_threads_seat_seed_per_seat() -> None:
    """The seed contract: seat N gets ``base_seed + N``. Same scan seed
    -> same per-seat seed -> same per-seat verdict on providers that
    honour seed.

    Inspects the per-seat Judge.verdict call to assert the seed kwarg
    matches the expected offset.
    """
    specs = [
        _make_spec("gemini", "attacker-as-judge"),
        _make_spec("gemini", "evaluator-as-judge"),
    ]
    panel = PanelJudge(specs=specs, seed=42)

    # Replace each inner Judge with an AsyncMock so we can inspect
    # what seed it was called with. Each Judge is the first element of
    # the (judge_obj, spec) tuple in panel._judges.
    seat_mocks: list[AsyncMock] = []
    new_judges: list[tuple[AsyncMock, JudgeSpec]] = []
    for _, spec in panel._judges:
        mock = AsyncMock()
        mock.verdict = AsyncMock(return_value=_stub_verdict())
        seat_mocks.append(mock)
        new_judges.append((mock, spec))
    panel._judges = new_judges  # type: ignore[assignment]

    await panel.verdict(prompt="probe", target_response="response")

    # Seat 0 should have been called with seed=42; seat 1 with seed=43.
    assert seat_mocks[0].verdict.await_count == 1
    assert seat_mocks[1].verdict.await_count == 1
    seed0 = seat_mocks[0].verdict.await_args.kwargs.get("seed")
    seed1 = seat_mocks[1].verdict.await_args.kwargs.get("seed")
    assert seed0 == 42, (
        f"seat 0 received seed={seed0}, expected the scan seed (42) -- "
        f"panel seed-threading regressed (#227)"
    )
    assert seed1 == 43, (
        f"seat 1 received seed={seed1}, expected base_seed + seat_index "
        f"(42 + 1 = 43) so per-seat seeds differ (avoid 3 identical samples)"
    )


@pytest.mark.asyncio
async def test_panel_judge_seed_none_propagates_as_none() -> None:
    """When the scan was launched without a ``--seed``, every seat
    receives ``seed=None`` -- the same behaviour ``Judge.verdict``
    documents for the silent-no-op providers."""
    specs = [_make_spec("gemini", "a"), _make_spec("gemini", "b")]
    panel = PanelJudge(specs=specs, seed=None)

    seat_mocks: list[AsyncMock] = []
    new_judges: list[tuple[AsyncMock, JudgeSpec]] = []
    for _, spec in panel._judges:
        mock = AsyncMock()
        mock.verdict = AsyncMock(return_value=_stub_verdict())
        seat_mocks.append(mock)
        new_judges.append((mock, spec))
    panel._judges = new_judges  # type: ignore[assignment]

    await panel.verdict(prompt="probe", target_response="response")

    for idx, mock in enumerate(seat_mocks):
        seat_seed = mock.verdict.await_args.kwargs.get("seed")
        assert seat_seed is None, (
            f"seat {idx} received seed={seat_seed}; expected None when the scan ran without --seed"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_verdict():
    """Construct a minimal JudgeVerdict-shaped object so the panel's
    aggregator doesn't crash."""
    from agent_guardian.agents.base import JudgeVerdict

    return JudgeVerdict(
        verdict="defended",
        reasoning="(stub for #227 seed-threading test)",
        confidence=1.0,
        marker=None,
        refused=False,
        observable_compromise=False,
        evaluator_attack=False,
        followup_probe="",
    )
