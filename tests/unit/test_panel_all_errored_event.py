"""Issue #260 — panel-all-errored must be observably distinct from
panel-needs_followup.

The rc38 matrix ran on a free-tier Gemini key that 429'd every call.
441/441 panel verdicts emitted ``majority=needs_followup,
confidence=0.00, agreement_fraction=1.0`` — IDENTICAL in shape to a
real unanimous needs_followup vote on a healthy panel. Downstream
consumers (events.jsonl readers, dashboards, gate logic) saw "panel
agreed" not "panel collapsed".

The fix: when EVERY seat raises before producing a JudgeVerdict, the
panel emits a structured payload with ``majority="error"``,
``confidence=null``, ``error_count=N``, ``errors=[...]`` so the
all-errored case is a first-class signal. The JudgeVerdict returned to
the agent loop is unchanged (``needs_followup``, the safe middle
ground) so the rest of the run loop is unaffected — only the event
shape diverges.

The SwarmCommander tracks a per-scan ``errors_panel_all_errored``
counter and, when ``>= 10`` consecutive panels collapse, fast-fails
the scan with a distinct exit code instead of running silently to a
``needs_followup`` "completion".
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_guardian.judges.panel import JudgeSpec, PanelJudge


class _RaisingJudge:
    """Stand-in for ``agent_guardian.agents.base.Judge`` that always raises.

    Simulates the rc38 matrix's 100% Gemini-429 condition where every
    panel seat threw ``_ResourceExhaustedError`` before producing a
    JudgeVerdict.
    """

    def __init__(self, exc_type: type[Exception] = RuntimeError, message: str = "boom") -> None:
        self._exc_type = exc_type
        self._message = message
        self.calls = 0

    async def verdict(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        raise self._exc_type(self._message)


def _two_seat_panel() -> tuple[PanelJudge, list[JudgeSpec]]:
    specs = [
        JudgeSpec(llm=MagicMock(), model="gemini-3.5-flash", family="gemini", label="seat-1"),
        JudgeSpec(llm=MagicMock(), model="gemini-3.5-flash", family="gemini", label="seat-2"),
    ]
    panel = PanelJudge(specs=specs)
    return panel, specs


@pytest.mark.asyncio
async def test_all_errored_panel_event_has_distinct_shape() -> None:
    """When every seat raises, the structured ``panel_verdict`` payload
    MUST carry ``majority="error"`` and a non-null ``error_count``, so
    a downstream consumer can distinguish "panel collapsed" from a real
    unanimous ``needs_followup`` vote.

    Pre-fix, both shapes were identical (``majority=needs_followup,
    confidence=0.00, agreement_fraction=1.0``) — this test pins the
    contract so #260's silent-failure path stays closed."""
    panel, specs = _two_seat_panel()
    panel._judges = [
        (_RaisingJudge(RuntimeError, "429 rate limit"), specs[0]),
        (_RaisingJudge(RuntimeError, "429 rate limit"), specs[1]),
    ]
    captured: list[dict[str, Any]] = []
    panel._event_emitter = captured.append  # type: ignore[assignment]

    await panel.verdict("p", "r")

    assert len(captured) == 1, "panel must emit exactly one verdict event"
    payload = captured[0]
    assert payload["majority"] == "error", (
        f"all-errored panel must publish majority='error' on the event "
        f"payload (got {payload['majority']!r}); without this #260's "
        f"441/441 silent-failure shape repeats."
    )
    assert payload["confidence"] is None, (
        "confidence MUST be null when no seat produced a real verdict — "
        "a numeric 0.0 is indistinguishable from a real low-confidence "
        "unanimous vote."
    )
    assert payload["error_count"] == 2
    assert isinstance(payload["errors"], list) and len(payload["errors"]) == 2
    # Each error entry carries enough context to triage without grepping
    # run.log: exception type, model id, family.
    err = payload["errors"][0]
    assert "type" in err and "model" in err and "family" in err


@pytest.mark.asyncio
async def test_partial_errored_panel_keeps_normal_shape() -> None:
    """When ONE seat raises and the other returns a real verdict, the
    panel keeps the existing single-vote degraded path (no
    ``majority="error"`` override). The error path is exclusively for
    the 100%-errored case."""
    from agent_guardian.models.judge import JudgeVerdict

    class _OkJudge:
        async def verdict(self, *args: Any, **kwargs: Any) -> JudgeVerdict:
            return JudgeVerdict(verdict="defended", confidence=0.9, reasoning="ok")

    panel, specs = _two_seat_panel()
    panel._judges = [
        (_OkJudge(), specs[0]),
        (_RaisingJudge(RuntimeError, "429"), specs[1]),
    ]
    captured: list[dict[str, Any]] = []
    panel._event_emitter = captured.append  # type: ignore[assignment]

    await panel.verdict("p", "r")

    payload = captured[0]
    assert payload["majority"] != "error", (
        "single-seat error is NOT an all-errored collapse; the existing "
        "degraded vote path must take precedence."
    )


def test_scan_completeness_carries_panel_error_counter() -> None:
    """``ScanCompleteness`` must surface ``errors_panel_all_errored``
    so the run.log + report.json carry a first-class count of how many
    panels collapsed (independent of the per-panel events). A
    consecutive-collapse threshold then drives the circuit-break."""
    from agent_guardian.models.scan import ScanCompleteness

    c = ScanCompleteness(
        agents_planned=5,
        agents_completed=5,
        terminated_by_counts={"success": 5},
        errors_panel_all_errored=441,
    )
    assert c.errors_panel_all_errored == 441
    dumped = c.model_dump()
    assert dumped["errors_panel_all_errored"] == 441
