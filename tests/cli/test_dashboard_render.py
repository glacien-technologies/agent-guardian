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


def _render_to_text(state: DashboardState, *, no_color: bool = False) -> str:
    console = Console(
        record=True,
        width=120,
        force_terminal=not no_color,
        color_system=None if no_color else "truecolor",
        no_color=no_color,
        theme=_AG_THEME,
    )
    console.print(make_dashboard(state))
    return console.export_text()


def test_initial_state_renders_all_pending_pills() -> None:
    """Empty state should list every known agent row in 'pending' status."""
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    text = _render_to_text(state)
    # All eleven rows show "pending"; recon row + 10 ASI rows.
    assert text.count("pending") >= len(AGENT_ROWS)


def test_group_composition_order_header_table_footer() -> None:
    """make_dashboard returns a Group with header → table → footer in order.

    When no budget caps are set, the progress bars are omitted so the
    Group has exactly three renderables.
    """
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    group = make_dashboard(state)
    assert isinstance(group, Group)
    renderables = list(group.renderables)
    assert len(renderables) == 3
    # The header and footer are Rich Panels; the middle slot is the table.
    types = [type(r).__name__ for r in renderables]
    assert types[0] == "Panel"
    assert types[1] == "Table"
    assert types[2] == "Panel"


def test_group_composition_includes_progress_when_caps_set() -> None:
    """When budget caps are configured the Group adds a Progress block."""
    state = DashboardState(
        scan_id="abc",
        target_ref="t",
        tier="auto",
        budget_tokens_cap=10_000,
        budget_tokens_spent=2_500,
        budget_usd_cap=0.25,
        budget_usd_spent=0.05,
    )
    group = make_dashboard(state)
    renderables = list(group.renderables)
    assert len(renderables) == 4
    assert type(renderables[2]).__name__ == "Progress"


def test_progress_bars_hidden_when_caps_none() -> None:
    """When no caps are set the rendered text contains no 'tokens' row."""
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    text = _render_to_text(state)
    # No "0 / 10,000" row, no "USD" progress label in the text.
    assert "tokens" not in text.lower()


def test_aivss_colour_threshold_low() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto", provisional_aivss=42)
    console = _record_console()
    console.print(make_dashboard(state))
    html = console.export_html(inline_styles=True)
    # aivss.low maps to green; check the rendered HTML contains it.
    assert "color: #008000" in html.lower() or "green" in html.lower()


def test_aivss_colour_threshold_high() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto", provisional_aivss=85)
    console = _record_console()
    console.print(make_dashboard(state))
    html = console.export_html(inline_styles=True)
    # aivss.high maps to red.
    assert "#800000" in html.lower() or "red" in html.lower()


def test_aivss_none_renders_em_dash() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto", provisional_aivss=None)
    text = _render_to_text(state)
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


def test_dashboard_lists_agent_findings_count() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    state.agent_findings["goal-hijack-agent"] = 4
    text = _render_to_text(state)
    assert "4" in text


def test_dashboard_lists_turn_progress_when_set() -> None:
    state = DashboardState(scan_id="abc", target_ref="t", tier="auto")
    state.agent_turns["tool-abuse-agent"] = (3, 12)
    text = _render_to_text(state)
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
    """A 10-event simulated scan must yield one swarm-board panel.

    The smoking-gun QA-002 regression was duplicate "AgentGuardian —
    swarm board" panels in scrollback after each event; replacing
    ``console.print(panel)`` with ``live.update(...)`` is what this
    test guards.
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
    assert text.count("AgentGuardian — swarm board") == 1


def test_live_region_includes_final_aivss_after_scan_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    console = _record_console()
    monkeypatch.setattr("agent_guardian.logging_setup._CONSOLE", console)

    async def _run() -> None:
        tui = ScanTUI(scan_id="scan-1", target_ref="testbench", tier="auto", console=console)
        async with tui:
            tui.handle_event(
                _make_event(
                    "checkpoint",
                    provisional_aivss=77,
                    decision=CheckpointDecision.CONTINUE,
                )
            )

    asyncio.run(_run())
    assert "77" in console.export_text()


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
