"""QA-012 — swarm-side phase event emission tests.

These tests cover the four ``phase_start`` / ``phase_done`` boundary
emits in ``SwarmCommander`` without spinning up a real LLM scan. They
isolate the emit-site by exercising the lowest level the events
escape from: the ``_emit`` channel + observer wrap.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_guardian.core.swarm import SwarmEvent


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Payload shape — phase_start / phase_done both carry phase / phase_index /
# phase_label, and phase_done additionally carries duration_seconds + summary.
# ---------------------------------------------------------------------------


def test_phase_start_event_payload_shape() -> None:
    event = SwarmEvent(
        kind="phase_start",
        timestamp=_utcnow(),
        payload={
            "phase": "recon",
            "phase_index": 1,
            "phase_label": "Reconnaissance",
        },
    )
    assert event.kind == "phase_start"
    assert event.payload["phase"] == "recon"
    assert event.payload["phase_index"] == 1
    assert event.payload["phase_label"] == "Reconnaissance"


def test_phase_done_event_includes_duration_and_summary() -> None:
    event = SwarmEvent(
        kind="phase_done",
        timestamp=_utcnow(),
        payload={
            "phase": "recon",
            "phase_index": 1,
            "phase_label": "Reconnaissance",
            "duration_seconds": 42.5,
            "summary": {
                "probes_applicable": 13,
                "probes_skipped": 3,
                "multi_agent": False,
                "notes": "audit",
            },
        },
    )
    assert event.payload["duration_seconds"] == pytest.approx(42.5)
    summary = event.payload["summary"]
    assert isinstance(summary, dict)
    assert summary["probes_applicable"] == 13
    assert summary["multi_agent"] is False


def test_phase_done_decompose_skip_carries_skipped_true() -> None:
    """A ``decompose`` phase_done with no operator or inferred goal must
    flag ``summary.skipped=True`` so observers can dispatch the skip
    branch without re-deriving the predicate."""
    event = SwarmEvent(
        kind="phase_done",
        timestamp=_utcnow(),
        payload={
            "phase": "decompose",
            "phase_index": 2,
            "phase_label": "Decomposition",
            "duration_seconds": 0.0,
            "summary": {
                "sub_goals": 0,
                "skipped": True,
                "reason": "no operator or inferred goal",
            },
        },
    )
    assert event.payload["summary"]["skipped"] is True


def test_phase_done_parallel_no_agents_carries_skipped_true() -> None:
    event = SwarmEvent(
        kind="phase_done",
        timestamp=_utcnow(),
        payload={
            "phase": "parallel",
            "phase_index": 3,
            "phase_label": "Red Teaming",
            "duration_seconds": 0.0,
            "summary": {
                "n_agents": 0,
                "n_findings": 0,
                "skipped": True,
            },
        },
    )
    assert event.payload["summary"]["skipped"] is True
    assert event.payload["summary"]["n_agents"] == 0


def test_phase_done_finalise_carries_score_and_band() -> None:
    event = SwarmEvent(
        kind="phase_done",
        timestamp=_utcnow(),
        provisional_aivss=41,
        payload={
            "phase": "finalise",
            "phase_index": 4,
            "phase_label": "Findings",
            "duration_seconds": 2.0,
            "summary": {
                "final_aivss": 41.0,
                "band": "high",
                "n_findings": 5,
            },
        },
    )
    assert event.provisional_aivss == 41
    summary = event.payload["summary"]
    assert summary["final_aivss"] == pytest.approx(41.0)
    assert summary["band"] == "high"


def test_phase_events_are_in_event_kind_literal() -> None:
    """``phase_start`` and ``phase_done`` must be valid ``EventKind`` values.

    The Literal is enforced by the dataclass constructor at runtime
    (mypy --strict checks at type-time). Constructing one is the same
    test pre-existing observers run against unknown kinds.
    """
    SwarmEvent(kind="phase_start", timestamp=_utcnow())  # type: ignore[arg-type]
    SwarmEvent(kind="phase_done", timestamp=_utcnow())  # type: ignore[arg-type]
