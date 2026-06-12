"""Issue #167 / tester PDF item 1 — recon-agent shows ``0/0`` Turns when
it actually completed via a path that emitted no progress events.

The CLI agent table renders ``turn_pair[0]/turn_pair[1]`` from
``state.agent_turns[agent]``. When ``recon_done`` fires on the white-box
early-return path with no ``probes_sent`` / ``turns`` count, the row
landed at ``(0, 0)`` — which renders as the literal "0/0" and reads as
"the run silently produced nothing".

This test locks the fix: ``(0, 0)`` renders as the same em-dash the
other "no useful number" cells use.
"""

from __future__ import annotations

from agent_guardian.ui._panel_render import _render_agent_table
from agent_guardian.ui.state import DashboardState


def _state_with_recon_turn_pair(turn_pair: tuple[int, int] | None) -> DashboardState:
    """Build a DashboardState with the recon-agent row set to the given
    turn-pair (or unset). Other agents stay defaults."""
    state = DashboardState(scan_id="t", target_ref="r", tier="T2_HIGH")  # type: ignore[arg-type]
    state.agent_status["recon-agent"] = "done"
    if turn_pair is not None:
        state.agent_turns["recon-agent"] = turn_pair
    return state


def _render_turns_cell(state: DashboardState) -> str:
    """Render the agent table and return the Turns cell for recon-agent."""
    from rich.console import Console

    table = _render_agent_table(state)
    console = Console(file=None, record=True, width=160)
    console.print(table)
    out = console.export_text()
    # Walk lines; find the recon-agent row. The Turns column is the 4th
    # space-separated cell (Agent / ASI / Status / Turns / Findings).
    for line in out.splitlines():
        if "recon-agent" in line:
            return line
    raise AssertionError(f"recon-agent row not found in:\n{out}")


def test_zero_turn_pair_renders_as_em_dash() -> None:
    """Tester PDF item 1: ``(0, 0)`` Turns must render as "—" so a
    completed recon-agent with no probe count doesn't read as a silent
    failure."""
    state = _state_with_recon_turn_pair((0, 0))
    row = _render_turns_cell(state)
    assert "0/0" not in row, f"(0, 0) must NOT render as 0/0, got: {row!r}"
    assert "—" in row, f"(0, 0) must render as em-dash, got: {row!r}"


def test_nonzero_turn_pair_still_renders_as_fraction() -> None:
    """Back-compat: a real turn count keeps the existing "n/N" rendering."""
    state = _state_with_recon_turn_pair((3, 5))
    row = _render_turns_cell(state)
    assert "3/5" in row, f"(3, 5) must render as 3/5, got: {row!r}"


def test_missing_turn_pair_renders_as_em_dash() -> None:
    """Pre-fix invariant preserved: an agent with no entry in
    ``agent_turns`` continues to render as "—"."""
    state = _state_with_recon_turn_pair(None)
    row = _render_turns_cell(state)
    assert "—" in row, f"missing turn-pair must render as em-dash, got: {row!r}"
