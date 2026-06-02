"""QA-002 — render tests for the swarm-board Live region.

The dashboard module is a pure function over :class:`DashboardState`.
These tests exercise it through a ``Console(record=True)`` so we
assert against the rendered text rather than re-implementing Rich's
ANSI emitter.

What matters here (the QA-002 acceptance criteria):

* exactly one panel renders on the initial empty state — no duplicate
  frames accumulate during state updates,
* the Group composition has header → table → (optional progress) →
  footer in that order,
* AIVSS bands paint with the right theme token,
* :class:`KeyboardInterrupt` cleanly tears down the Live region,
* progress bars are hidden when no caps are set.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any

import pytest
from rich.console import Console, Group

from agent_guardian.cli_tui import ScanTUI
from agent_guardian.core.swarm import CheckpointDecision, SwarmEvent
from agent_guardian.logging_setup import _AG_THEME, _reset_console_for_tests
from agent_guardian.ui.dashboard import AGENT_ROWS, DashboardState, make_dashboard
from tests._ansi import normalise_help


@pytest.fixture(autouse=True)
def _reset_console() -> Any:
    _reset_console_for_tests()
    yield
    _reset_console_for_tests()


def _record_console(width: int = 120) -> Console:
    return Console(
        record=True,
        width=width,
        force_terminal=True,
        color_system="truecolor",
        theme=_AG_THEME,
    )


def _render_to_text(
    state: DashboardState,
    *,
    no_color: bool = False,
    legacy: bool = False,
    width: int = 120,
) -> str:
    console = Console(
        record=True,
        width=width,
        force_terminal=not no_color,
        color_system=None if no_color else "truecolor",
        no_color=no_color,
        theme=_AG_THEME,
    )
    console.print(make_dashboard(state, legacy=legacy))
    return console.export_text()


def test_initial_state_renders_all_pending_pills_legacy() -> None:
    """The legacy-board renderable lists every known agent row in 'pending'.

    QA-012 — the default composition is phase-based and shows panel
    summaries instead of a full pending pill per agent on the very
    first frame. The original assertion holds on the ``--legacy-board``
    surface, which the test exercises directly.
    """
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    text = _render_to_text(state, legacy=True)
    # All eleven rows show "pending"; recon row + 10 ASI rows.
    assert text.count("pending") >= len(AGENT_ROWS)


def test_group_composition_order_three_phase_panels() -> None:
    """make_dashboard returns a Group composing the three phase panels.

    QA-012 — the new default composition is
    ``Group(recon_panel, red_team_panel, findings_panel)``. The Plan
    panel is opt-in via ``plan_panel=`` and the debug-feed renderable
    is opt-in via ``debug_feed=``; both default to None so a fresh
    state yields exactly three Panel renderables.
    """
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    group = make_dashboard(state)
    assert isinstance(group, Group)
    renderables = list(group.renderables)
    assert len(renderables) == 3
    # All three phase blocks are Rich Panels.
    types = [type(r).__name__ for r in renderables]
    assert types == ["Panel", "Panel", "Panel"]


def test_legacy_group_composition_order_header_table_footer() -> None:
    """``legacy=True`` preserves the pre-QA-012 flat composition."""
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    group = make_dashboard(state, legacy=True)
    assert isinstance(group, Group)
    renderables = list(group.renderables)
    assert len(renderables) == 3
    types = [type(r).__name__ for r in renderables]
    assert types == ["Panel", "Table", "Panel"]


def test_legacy_group_composition_includes_progress_when_caps_set() -> None:
    """``legacy=True`` + budget caps -> Progress block in middle of group."""
    state = DashboardState(
        scan_id="abc",
        target_ref="t",
        tier="auto",
        budget_tokens_cap=10_000,
        budget_tokens_spent=2_500,
        budget_usd_cap=0.25,
        budget_usd_spent=0.05,
    )
    group = make_dashboard(state, legacy=True)
    renderables = list(group.renderables)
    assert len(renderables) == 4
    assert type(renderables[2]).__name__ == "Progress"


def test_progress_bars_hidden_when_caps_none_legacy() -> None:
    """When no caps are set the legacy renderable has no 'tokens' row."""
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    text = _render_to_text(state, legacy=True)
    assert "tokens" not in text.lower()


def test_aivss_colour_threshold_low_legacy() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto", provisional_aivss=42)
    console = _record_console()
    console.print(make_dashboard(state, legacy=True))
    html = console.export_html(inline_styles=True)
    # aivss.low maps to green; check the rendered HTML contains it.
    assert "color: #008000" in html.lower() or "green" in html.lower()


def test_aivss_colour_threshold_high_legacy() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto", provisional_aivss=85)
    console = _record_console()
    console.print(make_dashboard(state, legacy=True))
    html = console.export_html(inline_styles=True)
    # aivss.high maps to red.
    assert "#800000" in html.lower() or "red" in html.lower()


def test_aivss_none_renders_em_dash_legacy() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto", provisional_aivss=None)
    text = _render_to_text(state, legacy=True)
    assert "—" in text


def test_no_color_mode_strips_ansi() -> None:
    """Console(no_color=True) yields ANSI-free output for log/file capture."""
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    text = _render_to_text(state, no_color=True)
    assert "\x1b[" not in text


def test_make_dashboard_is_pure_no_side_effects() -> None:
    """Two calls with the same state produce equivalent renderables."""
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    a = _render_to_text(state)
    b = _render_to_text(state)
    assert a == b


def test_dashboard_lists_agent_findings_count_legacy() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    state.agent_findings["goal-hijack-agent"] = 4
    text = _render_to_text(state, legacy=True)
    assert "4" in text


def test_dashboard_lists_turn_progress_when_set_legacy() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    state.agent_turns["tool-abuse-agent"] = (3, 12)
    text = _render_to_text(state, legacy=True)
    assert "3/12" in text


# ---------------------------------------------------------------------------
# ScanTUI integration — exactly one panel in the recorded scrollback during
# a simulated 10-event scan.
# ---------------------------------------------------------------------------


def _make_event(kind: str, **extra: Any) -> SwarmEvent:
    return SwarmEvent(kind=kind, timestamp=time.monotonic(), **extra)  # type: ignore[arg-type]


def test_live_region_renders_exactly_one_panel_during_simulated_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 10-event simulated scan must yield one Phase 1 panel in scrollback.

    The smoking-gun QA-002 regression was duplicate panels in
    scrollback after each event; replacing ``console.print(panel)``
    with ``live.update(...)`` is what this test guards. The QA-012
    composition surfaces a "Phase 1 · Reconnaissance" title in the
    final frame; the duplicate-frame regression would replay it once
    per event.
    """
    console = _record_console(width=140)
    monkeypatch.setattr("agent_guardian.logging_setup._CONSOLE", console)

    async def _run() -> None:
        tui = ScanTUI(scan_id="scan-1", target_ref="testbench", tier="auto", console=console)
        async with tui:
            tui.handle_event(_make_event("recon_start"))
            tui.handle_event(_make_event("recon_done"))
            for agent in (
                "goal-hijack-agent",
                "tool-abuse-agent",
                "privilege-agent",
            ):
                tui.handle_event(_make_event("agent_start", agent=agent))
                tui.handle_event(
                    _make_event(
                        "agent_progress",
                        agent=agent,
                        payload={"turn": 2, "max_turns": 4},
                    )
                )
                tui.handle_event(
                    _make_event("agent_done", agent=agent, payload={"findings_count": 1})
                )
            tui.handle_event(
                _make_event(
                    "checkpoint",
                    provisional_aivss=42,
                    decision=CheckpointDecision.CONTINUE,
                )
            )
            tui.handle_event(_make_event("scan_done", provisional_aivss=42))

    asyncio.run(_run())

    text = console.export_text()
    # Phase 1 panel rendered exactly once — duplicate-frame regression
    # would replay the panel border per event. The phase tag is in the
    # final frame's title once.
    assert text.count("Phase 1 · Reconnaissance") == 1
    # Phase 3 (Findings) panel rendered exactly once with the totals
    # we projected from the three agent_done events (one finding each).
    assert text.count("Phase 3 · Findings") == 1


def test_live_region_includes_final_aivss_after_scan_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provisional AIVSS lands on state on checkpoint; legacy footer
    surfaces it directly. The QA-012 phase composition shows AIVSS as
    part of the post-Live reproducibility line emitted by ``_run_scan``;
    here we exercise the legacy-board path which still renders the
    footer for the one-release deprecation window.
    """
    console = _record_console()
    monkeypatch.setattr("agent_guardian.logging_setup._CONSOLE", console)

    async def _run() -> ScanTUI:
        tui = ScanTUI(
            scan_id="scan-1",
            target_ref="testbench",
            tier="auto",
            console=console,
            legacy_board=True,
        )
        async with tui:
            tui.handle_event(
                _make_event(
                    "checkpoint",
                    provisional_aivss=77,
                    decision=CheckpointDecision.CONTINUE,
                )
            )
        return tui

    tui = asyncio.run(_run())
    # State carries the provisional AIVSS regardless of presentation mode.
    assert tui._state.provisional_aivss == 77
    # Legacy footer renders the value directly.
    assert "77" in console.export_text()


def test_agent_table_renders_plan_label_and_attachment_count_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PhaseC — the Turns cell widens with a (plan: X) suffix and [+K att] glyph."""
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    state.agent_turns["tool-abuse-agent"] = (2, 4)
    state.agent_plan_label["tool-abuse-agent"] = "demo-plan"
    state.agent_attachment_counts["tool-abuse-agent"] = 3
    # Pin a wide Console so the Turns column does not get squeezed and
    # truncated to "+3 at…". CRITICAL: the autouse conftest sets
    # ``TERM=dumb`` and the helper passes ``force_terminal=True``;
    # together that flips Rich's ``is_dumb_terminal`` ON, which then
    # clamps Console size to (80, 25) regardless of the explicit
    # ``width=`` we pass. Override TERM here so Rich honours width=400.
    # Belt-and-braces: normalise_help collapses any wrap-breaks too.
    monkeypatch.setenv("TERM", "xterm-256color")
    text = normalise_help(_render_to_text(state, legacy=True, width=400))
    assert "2/4" in text
    assert "plan: demo-plan" in text
    assert "+3 att" in text


def test_agent_progress_payload_populates_plan_and_attachment_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PhaseC — cli_tui projects plan_name + attachments_count from payload."""
    console = _record_console()
    monkeypatch.setattr("agent_guardian.logging_setup._CONSOLE", console)

    async def _run() -> ScanTUI:
        tui = ScanTUI(scan_id="scan-1", target_ref="testbench", tier="auto", console=console)
        async with tui:
            tui.handle_event(_make_event("agent_start", agent="tool-abuse-agent"))
            tui.handle_event(
                _make_event(
                    "agent_progress",
                    agent="tool-abuse-agent",
                    payload={
                        "turn": 2,
                        "max_turns": 4,
                        "plan_name": "demo-plan",
                        "plan_total_turns": 4,
                        "attachments_count": 2,
                    },
                )
            )
        return tui

    tui = asyncio.run(_run())
    assert tui._state.agent_turns["tool-abuse-agent"] == (2, 4)
    assert tui._state.agent_plan_label["tool-abuse-agent"] == "demo-plan"
    assert tui._state.agent_attachment_counts["tool-abuse-agent"] == 2


def test_keyboard_interrupt_tears_down_live_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """KeyboardInterrupt mid-scan must exit the async context cleanly.

    We assert two invariants:
      * the ``async with`` block exits without raising on the way out,
      * after exit, the Live region is stopped (``_live is None``).
    """
    console = _record_console()
    monkeypatch.setattr("agent_guardian.logging_setup._CONSOLE", console)

    async def _run() -> ScanTUI:
        tui = ScanTUI(scan_id="scan-1", target_ref="testbench", tier="auto", console=console)
        with contextlib.suppress(KeyboardInterrupt):
            async with tui:
                tui.handle_event(_make_event("recon_start"))
                raise KeyboardInterrupt
        return tui

    tui = asyncio.run(_run())
    assert tui._live is None
