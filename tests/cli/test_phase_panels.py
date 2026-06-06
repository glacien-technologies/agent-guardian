"""QA-012 — render tests for the three-phase Live composition.

These tests guard the new composition contract:

* :func:`make_dashboard` returns a ``rich.console.Group`` containing
  three phase panels (recon, red team, findings) in order;
* an optional Plan panel is prepended when ``current_phase == "plan"``
  and dropped from later frames;
* an optional debug-feed renderable is appended below Phase 3 (the
  QA-005 attack feed lives there in ``--debug`` mode);
* ``legacy=True`` returns the pre-QA-012 flat agent table for the
  ``--legacy-board`` opt-in;
* each individual panel renders coherently for its lifecycle stage.

The QA-002 invariants ("exactly one Live frame at a time, no duplicate
panels in scrollback") are exercised separately by
``test_dashboard_render.py``; here we focus on the new composition.
"""

from __future__ import annotations

from typing import Any

import pytest
from rich.console import Console, Group
from rich.panel import Panel

from agent_guardian.cli_tui import ScanTUI
from agent_guardian.core.swarm import SwarmEvent
from agent_guardian.logging_setup import _AG_THEME, _reset_console_for_tests
from agent_guardian.ui.dashboard import DashboardState, make_dashboard
from agent_guardian.ui.findings_panel import FindingRow, build_findings_panel
from agent_guardian.ui.recon_panel import ReconSummary, build_recon_panel
from agent_guardian.ui.red_team_panel import build_red_team_panel


@pytest.fixture(autouse=True)
def _reset_console() -> Any:
    _reset_console_for_tests()
    yield
    _reset_console_for_tests()


def _record(width: int = 140) -> Console:
    return Console(
        record=True,
        width=width,
        force_terminal=True,
        color_system="truecolor",
        theme=_AG_THEME,
    )


def _text(renderable: Any, *, width: int = 140) -> str:
    console = _record(width=width)
    console.print(renderable)
    return console.export_text()


# ---------------------------------------------------------------------------
# Phase 1 — Recon panel.
# ---------------------------------------------------------------------------


def test_recon_panel_pending_when_no_summary() -> None:
    state = DashboardState(scan_id="s", target_ref="https://x", tier="auto")
    state.current_phase = "plan"
    panel = build_recon_panel(state)
    text = _text(panel)
    assert "Phase 1 · Reconnaissance" in text
    assert "waiting on swarm start" in text


def test_recon_panel_running_with_partial_summary() -> None:
    state = DashboardState(scan_id="s", target_ref="https://x", tier="auto")
    state.current_phase = "recon"
    state.recon_summary = ReconSummary(
        goal="hijack PII flow",
        target_ref="https://x",
        recon_probes=8,
        multi_agent=False,
        duration_seconds=0.0,
        status="running",
    )
    state.elapsed_seconds = 12.0
    state.phase_durations["recon"] = 12.0
    text = _text(build_recon_panel(state))
    assert "running" in text
    assert "hijack PII flow" in text
    assert "8 capability probes" in text


def test_recon_panel_done_full() -> None:
    state = DashboardState(scan_id="s", target_ref="https://x", tier="auto")
    state.current_phase = "decompose"  # still BEFORE parallel -> full panel
    state.recon_summary = ReconSummary(
        goal="capability audit",
        target_ref="https://x",
        recon_probes=13,
        multi_agent=False,
        duration_seconds=90.0,
        status="done",
    )
    text = _text(build_recon_panel(state))
    assert "capability audit" in text
    assert "13 capability probes" in text


def test_recon_panel_collapsed_when_parallel_active() -> None:
    state = DashboardState(scan_id="s", target_ref="https://x", tier="auto")
    state.current_phase = "parallel"
    state.recon_summary = ReconSummary(
        goal="g",
        target_ref="https://x",
        probes_applicable=13,
        probes_skipped=3,
        multi_agent=False,
        duration_seconds=90.0,
        status="done",
    )
    state.phase_durations["recon"] = 90.0
    text = _text(build_recon_panel(state))
    # Collapsed form: one line containing the phase title + duration.
    assert "Phase 1 · Reconnaissance" in text
    assert "done" in text
    # The detail rows ("what we found:", goal, target labels) are dropped.
    assert "what we found" not in text


# ---------------------------------------------------------------------------
# Phase 2 — Red Teaming panel.
# ---------------------------------------------------------------------------


def test_red_team_panel_queued_when_recon_active() -> None:
    state = DashboardState(scan_id="s", target_ref="https://x", tier="auto")
    state.current_phase = "recon"
    text = _text(build_red_team_panel(state))
    assert "Phase 2 · Red Teaming" in text
    assert "queued" in text.lower()


def test_red_team_panel_compact_summary_when_parallel() -> None:
    """QA-074 — during the run the panel is a THIN summary (counts + budget),
    NOT the full agent table; the table would fight with the live verdict feed
    scrolling above. The full table renders only once red teaming completes."""
    state = DashboardState(scan_id="s", target_ref="https://x", tier="auto")
    state.current_phase = "parallel"
    state.agent_status["goal-hijack-agent"] = "running"
    state.agent_status["tool-abuse-agent"] = "done"
    state.agent_findings["tool-abuse-agent"] = 2
    state.budget_usd_cap = 0.10
    state.budget_usd_spent = 0.03
    text = _text(build_red_team_panel(state))
    assert "Phase 2 · Red Teaming" in text
    # Compact summary surfaces live counts...
    assert "agents done" in text
    assert "2 findings" in text
    # ...but withholds the per-agent table during the run.
    assert "goal-hijack-agent" not in text


def test_red_team_panel_full_table_when_finalise() -> None:
    """QA-074 — once red teaming completes the full per-agent table renders as
    the stable final status (the inverse of the old collapse-on-done shape)."""
    state = DashboardState(scan_id="s", target_ref="https://x", tier="auto")
    state.current_phase = "finalise"
    state.agent_status["goal-hijack-agent"] = "done"
    state.agent_findings["goal-hijack-agent"] = 4
    state.phase_durations["parallel"] = 120.0
    text = _text(build_red_team_panel(state))
    assert "Phase 2 · Red Teaming" in text
    assert "done" in text
    # Full table is present at completion (the per-agent rows render).
    assert "goal-hijack-agent" in text


# ---------------------------------------------------------------------------
# Phase 3 — Findings panel.
# ---------------------------------------------------------------------------


def test_findings_panel_empty_placeholder() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    text = _text(build_findings_panel(state))
    assert "Phase 3 · Findings" in text
    assert "Findings will appear here" in text


def test_findings_panel_severity_grouped_order() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.findings_streaming = (
        FindingRow(probe_id="P-LOW", agent="a1", severity="low", evidence="low ev"),
        FindingRow(probe_id="P-HIGH", agent="a2", severity="high", evidence="high ev"),
        FindingRow(probe_id="P-CRIT", agent="a3", severity="critical", evidence="crit ev"),
        FindingRow(probe_id="P-MED", agent="a4", severity="medium", evidence="med ev"),
    )
    text = _text(build_findings_panel(state))
    # CRITICAL header must appear before HIGH which must appear before MEDIUM
    # and LOW.
    crit_idx = text.index("CRITICAL")
    high_idx = text.index("HIGH")
    med_idx = text.index("MEDIUM")
    low_idx = text.index("LOW")
    assert crit_idx < high_idx < med_idx < low_idx
    # Each probe id renders.
    for pid in ("P-CRIT", "P-HIGH", "P-MED", "P-LOW"):
        assert pid in text


def test_findings_panel_row_shape() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.findings_streaming = (
        FindingRow(
            probe_id="ASI01-GH-004",
            agent="goal-hijack-agent",
            severity="high",
            evidence="prompt injection succeeded",
        ),
    )
    text = _text(build_findings_panel(state))
    # Row: probe_id · agent · evidence
    assert "ASI01-GH-004" in text
    assert "goal-hijack-agent" in text
    assert "prompt injection succeeded" in text


def test_findings_panel_title_has_totals() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.findings_streaming = (
        FindingRow(probe_id="A", agent="x", severity="critical"),
        FindingRow(probe_id="B", agent="y", severity="high"),
        FindingRow(probe_id="C", agent="z", severity="high"),
    )
    text = _text(build_findings_panel(state))
    assert "3 total" in text
    assert "1 critical" in text
    assert "2 high" in text


# ---------------------------------------------------------------------------
# Composition — make_dashboard.
# ---------------------------------------------------------------------------


def test_make_dashboard_composes_three_panels_by_default() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "recon"
    group = make_dashboard(state)
    assert isinstance(group, Group)
    renderables = list(group.renderables)
    # No plan, no debug_feed -> exactly 3 panels.
    assert len(renderables) == 3
    types = [type(r).__name__ for r in renderables]
    assert types == ["Panel", "Panel", "Panel"]


def test_make_dashboard_with_plan_panel_prepends_it() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "plan"
    plan = Panel("plan body", title="Scan plan · cli-abc")
    group = make_dashboard(state, plan_panel=plan)
    assert isinstance(group, Group)
    renderables = list(group.renderables)
    assert len(renderables) == 4
    assert renderables[0] is plan


def test_make_dashboard_drops_plan_panel_after_phase_advances() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "recon"
    plan = Panel("plan body", title="Scan plan · cli-abc")
    group = make_dashboard(state, plan_panel=plan)
    renderables = list(group.renderables)
    assert len(renderables) == 3
    assert plan not in renderables


def test_make_dashboard_with_debug_feed_appends_below_findings() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "parallel"
    feed = Panel("attack feed", title="attack feed")
    group = make_dashboard(state, debug_feed=feed)
    renderables = list(group.renderables)
    # 3 phase panels + 1 debug feed appended last.
    assert len(renderables) == 4
    assert renderables[-1] is feed


def test_make_dashboard_legacy_flag_returns_flat_renderable() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    group = make_dashboard(state, legacy=True)
    assert isinstance(group, Group)
    # Legacy composition: header (Panel) + table (Table) + footer (Panel).
    renderables = list(group.renderables)
    types = [type(r).__name__ for r in renderables]
    assert types == ["Panel", "Table", "Panel"]


def test_make_dashboard_legacy_flag_renders_swarm_board_title() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    text = _text(make_dashboard(state, legacy=True))
    # The legacy renderer's header panel title still says "swarm board".
    assert "AgentGuardian — swarm board" in text


def test_make_dashboard_is_pure_two_calls_equivalent() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "parallel"
    a = _text(make_dashboard(state))
    b = _text(make_dashboard(state))
    assert a == b


# ---------------------------------------------------------------------------
# cli_tui — phase event handling.
# ---------------------------------------------------------------------------


def _phase_event(kind: str, **payload: Any) -> SwarmEvent:
    import time as _t

    return SwarmEvent(kind=kind, timestamp=_t.monotonic(), payload=payload)  # type: ignore[arg-type]


def test_handle_event_advances_current_phase_on_phase_start() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_start",
            phase="parallel",
            phase_index=3,
            phase_label="Red Teaming",
        )
    )
    assert tui._state.current_phase == "parallel"


def test_handle_event_stores_phase_duration_on_phase_done() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_done",
            phase="recon",
            phase_index=1,
            phase_label="Reconnaissance",
            duration_seconds=42.5,
            summary={
                "probes_applicable": 13,
                "probes_skipped": 3,
                "multi_agent": False,
                "notes": "",
            },
        )
    )
    assert tui._state.phase_durations["recon"] == 42.5


def test_handle_event_populates_recon_summary_on_phase_done_recon() -> None:
    tui = ScanTUI(scan_id="s", target_ref="https://x", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_done",
            phase="recon",
            phase_index=1,
            phase_label="Reconnaissance",
            duration_seconds=10.0,
            summary={
                "probes_applicable": 8,
                "probes_skipped": 2,
                "multi_agent": True,
                "notes": "audit",
                "inferred_goal": "g",
            },
        )
    )
    summary = tui._state.recon_summary
    assert summary is not None
    assert summary.probes_applicable == 8
    assert summary.probes_skipped == 2
    assert summary.multi_agent is True
    assert summary.goal == "g"
    assert summary.status == "done"


def test_handle_event_phase_done_advances_to_next_phase() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_done",
            phase="recon",
            phase_index=1,
            phase_label="Reconnaissance",
            duration_seconds=1.0,
            summary={
                "probes_applicable": 0,
                "probes_skipped": 0,
                "multi_agent": False,
                "notes": "",
            },
        )
    )
    # After recon done, current_phase advances to decompose.
    assert tui._state.current_phase == "decompose"


def test_handle_event_phase_done_finalise_goes_to_done() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_done",
            phase="finalise",
            phase_index=4,
            phase_label="Findings",
            duration_seconds=2.0,
            summary={"final_aivss": 41, "band": "high", "n_findings": 5},
        )
    )
    assert tui._state.current_phase == "done"


def test_agent_done_projects_findings_into_stream() -> None:
    import time as _t

    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        SwarmEvent(
            kind="agent_done",
            timestamp=_t.monotonic(),  # type: ignore[arg-type]
            agent="goal-hijack-agent",
            payload={"findings_count": 3},
        )
    )
    assert len(tui._state.findings_streaming) == 3
    assert all(r.agent == "goal-hijack-agent" for r in tui._state.findings_streaming)


def test_agent_done_zero_findings_does_not_grow_stream() -> None:
    import time as _t

    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        SwarmEvent(
            kind="agent_done",
            timestamp=_t.monotonic(),  # type: ignore[arg-type]
            agent="goal-hijack-agent",
            payload={"findings_count": 0},
        )
    )
    assert len(tui._state.findings_streaming) == 0


def test_next_phase_after_unknown_returns_done() -> None:
    from agent_guardian.cli_tui import _next_phase_after

    assert _next_phase_after("bogus") == "done"
    assert _next_phase_after("done") == "done"


def test_phase_start_unknown_phase_ignored() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    starting_phase = tui._state.current_phase
    tui.handle_event(
        _phase_event(
            "phase_start",
            phase="not-a-phase",
            phase_index=99,
            phase_label="Bogus",
        )
    )
    # Unknown phase is silently ignored.
    assert tui._state.current_phase == starting_phase


def test_phase_start_known_phase_seeds_duration_key() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_start",
            phase="recon",
            phase_index=1,
            phase_label="Reconnaissance",
        )
    )
    assert tui._state.phase_durations["recon"] == 0.0


def test_phase_done_missing_phase_key_ignored() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    starting_durations = dict(tui._state.phase_durations)
    tui.handle_event(_phase_event("phase_done", duration_seconds=1.0))
    # No phase key -> no mutation.
    assert tui._state.phase_durations == starting_durations


def test_phase_done_decompose_skip_does_not_clobber_recon_summary() -> None:
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_done",
            phase="decompose",
            phase_index=2,
            phase_label="Decomposition",
            duration_seconds=0.0,
            summary={"sub_goals": 0, "skipped": True, "reason": "no goal"},
        )
    )
    assert tui._state.recon_summary is None
    assert tui._state.current_phase == "parallel"


def test_red_team_panel_active_with_only_token_cap() -> None:
    """Cover the progress-only-tokens branch in ``_render_progress``."""
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "parallel"
    state.budget_tokens_cap = 100_000
    state.budget_tokens_spent = 25_000
    # Render through the panel to exercise the table-only-tokens code path.
    text = _text(build_red_team_panel(state))
    assert "Phase 2 · Red Teaming" in text


def test_recon_panel_done_zero_duration_falls_back_to_zero_string() -> None:
    """Cover the ``_format_duration`` zero-second branch."""
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "parallel"
    state.recon_summary = ReconSummary(
        goal="g",
        target_ref="t",
        probes_applicable=0,
        probes_skipped=0,
        multi_agent=False,
        duration_seconds=0.0,
        status="done",
    )
    state.phase_durations["recon"] = 0.0
    text = _text(build_recon_panel(state))
    assert "0s" in text


def test_recon_panel_full_with_notes_renders_notes_row() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "recon"
    state.recon_summary = ReconSummary(
        goal="g",
        target_ref="t",
        probes_applicable=5,
        probes_skipped=1,
        multi_agent=True,
        duration_seconds=10.0,
        status="done",
        notes="recon notes",
    )
    text = _text(build_recon_panel(state))
    assert "recon notes" in text


def test_recon_panel_full_multi_agent_yes() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "recon"
    state.recon_summary = ReconSummary(
        goal="g",
        target_ref="t",
        probes_applicable=5,
        probes_skipped=0,
        multi_agent=True,
        duration_seconds=10.0,
        status="done",
    )
    text = _text(build_recon_panel(state))
    assert "multi-agent: yes" in text


def test_red_team_collapsed_handles_zero_durations() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "done"
    state.elapsed_seconds = 0.0
    # No phase_durations set -> collapsed path falls back to elapsed - recon.
    text = _text(build_red_team_panel(state))
    assert "Phase 2 · Red Teaming" in text


def test_make_dashboard_plan_panel_with_debug_feed_full_composition() -> None:
    state = DashboardState(scan_id="s", target_ref="t", tier="auto")
    state.current_phase = "plan"
    plan = Panel("plan body", title="Scan plan · cli-abc")
    feed = Panel("attack feed body", title="attack feed")
    group = make_dashboard(state, plan_panel=plan, debug_feed=feed)
    renderables = list(group.renderables)
    # plan + 3 phase panels + debug_feed = 5 total
    assert len(renderables) == 5
    assert renderables[0] is plan
    assert renderables[-1] is feed


def test_phase_done_skip_branch_does_not_overwrite_recon() -> None:
    """A skip-branch ``phase_done("decompose")`` must NOT touch recon_summary."""
    tui = ScanTUI(scan_id="s", target_ref="t", tier="auto")
    tui.handle_event(
        _phase_event(
            "phase_done",
            phase="recon",
            phase_index=1,
            phase_label="Reconnaissance",
            duration_seconds=1.0,
            summary={
                "probes_applicable": 5,
                "probes_skipped": 1,
                "multi_agent": False,
                "notes": "",
            },
        )
    )
    summary_before = tui._state.recon_summary
    tui.handle_event(
        _phase_event(
            "phase_done",
            phase="decompose",
            phase_index=2,
            phase_label="Decomposition",
            duration_seconds=0.0,
            summary={"sub_goals": 0, "skipped": True, "reason": "no goal"},
        )
    )
    assert tui._state.recon_summary is summary_before
