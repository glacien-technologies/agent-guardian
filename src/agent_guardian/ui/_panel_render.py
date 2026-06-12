"""Shared private render helpers for the swarm-board panels.

This module exists solely to sever the static import cycle CodeQL
flagged between :mod:`agent_guardian.ui.dashboard` and
:mod:`agent_guardian.ui.red_team_panel`. Both modules need the same
two helpers — ``_render_agent_table`` and ``_render_progress`` — and
historically lived together in ``dashboard``; the red-team panel
imported them lazily inside ``_active_panel`` to keep the *runtime*
cycle out. CodeQL inspects the *static* import graph though, so the
lazy import still tripped its "cyclic imports" rule.

Hoisting these two helpers into a neutral leaf module (this file)
removes the static dependency edge from ``red_team_panel`` back to
``dashboard`` without changing observable behaviour. The helpers are
module-private (``_``-prefixed) and are consumed only by the two
sibling modules in this package; the blast radius is contained.

Keep this module free of any imports from sibling panel modules or
``dashboard`` — it MUST remain a leaf to fulfil its single purpose.
"""

from __future__ import annotations

from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from agent_guardian.ui.state import AGENT_ROWS, AgentStatus, DashboardState

__all__ = ["_render_agent_table", "_render_progress"]


_STATUS_STYLE: dict[AgentStatus, str] = {
    "pending": "status.pending",
    "running": "status.running",
    "done": "status.done",
    "error": "status.error",
    "skipped": "status.skipped",
}


def _render_agent_table(state: DashboardState) -> Table:
    """Agent rows: name, ASI, status pill, findings count, turn progress."""
    table = Table(expand=True, show_lines=False, padding=(0, 1))
    table.add_column("Agent", no_wrap=True)
    table.add_column("ASI", justify="center", no_wrap=True)
    table.add_column("Status", justify="left", no_wrap=True)
    table.add_column("Turns", justify="right", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)

    for name, asi in AGENT_ROWS:
        status: AgentStatus = state.agent_status.get(name, "pending")
        status_style = _STATUS_STYLE[status]
        asi_style = f"asi.{asi}" if asi.startswith("ASI") else "status.pending"
        turn_pair = state.agent_turns.get(name)
        # Tester PDF item 1 — a completed agent with ``(0, 0)`` turns
        # reads as "0/0" which looks like the run silently produced
        # nothing. Show "—" for a genuinely-zero-turn run AND for a
        # completed recon-agent that emitted no progress events (the
        # white-box early-return path), so the cell is consistent with
        # the rest of the "no useful number" indicators in the table.
        turn_str = f"{turn_pair[0]}/{turn_pair[1]}" if turn_pair and turn_pair != (0, 0) else "—"
        # PhaseC — append plan badge + attachment glyph when present.
        plan_label = state.agent_plan_label.get(name, "")
        if plan_label:
            turn_str = f"{turn_str} (plan: {plan_label})"
        att_count = state.agent_attachment_counts.get(name, 0)
        if att_count > 0:
            turn_str = f"{turn_str} [+{att_count} att]"
        table.add_row(
            Text(name, style=status_style),
            Text(asi, style=asi_style),
            Text(status, style=status_style),
            Text(turn_str, style="status.pending"),
            Text(str(state.agent_findings.get(name, 0))),
        )
    return table


def _render_progress(state: DashboardState) -> Progress | None:
    """Token + USD progress bars. ``None`` when both caps are unset."""
    if state.budget_tokens_cap is None and state.budget_usd_cap is None:
        return None
    progress = Progress(
        TextColumn("[brand.dim]{task.description}"),
        BarColumn(complete_style="brand", finished_style="brand"),
        TextColumn("[brand.dim]{task.fields[suffix]}"),
        expand=True,
        transient=False,
        disable=False,
    )
    if state.budget_tokens_cap is not None:
        task_id_tokens = progress.add_task(
            "tokens",
            total=float(state.budget_tokens_cap),
            suffix=f"{state.budget_tokens_spent:,} / {state.budget_tokens_cap:,}",
        )
        # Use ``update`` for fractional completion (the Progress ``add_task``
        # ``completed`` arg is typed ``int``; ``update`` accepts float).
        progress.update(task_id_tokens, completed=float(state.budget_tokens_spent))
    if state.budget_usd_cap is not None:
        task_id_usd = progress.add_task(
            "usd",
            total=state.budget_usd_cap,
            suffix=f"${state.budget_usd_spent:.4f} / ${state.budget_usd_cap:.4f}",
        )
        progress.update(task_id_usd, completed=state.budget_usd_spent)
    return progress
