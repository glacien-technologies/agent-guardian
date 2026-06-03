"""Rich Live-region renderable for the AgentGuardian scan TUI (QA-002).

This module owns the *single source of truth* for what the scrollback
shows during a scan. As of QA-012 the composition is a four-part
``rich.console.Group``:

* (optional) Phase 0 — the QA-011 Plan panel, rendered only during the
  pre-swarm wait (``state.current_phase == "plan"``);
* Phase 1 — :func:`agent_guardian.ui.recon_panel.build_recon_panel`;
* Phase 2 — :func:`agent_guardian.ui.red_team_panel.build_red_team_panel`;
* Phase 3 — :func:`agent_guardian.ui.findings_panel.build_findings_panel`.

The renderer is **pure** — :func:`make_dashboard` is side-effect free
and only consumes a :class:`DashboardState`. Callers update the state
and pass it to ``Live.update(make_dashboard(state))`` each tick. This
keeps the smoking-gun race the old TUI had (a ``console.print(panel)``
per event accumulating duplicate frames in scrollback) impossible by
construction — there is exactly one renderable at any moment and Rich
re-paints it in place. The QA-002 invariant is preserved by
construction: the Group is one renderable, and the Plan panel is
dropped from later frames so it never duplicates in scrollback.

A ``legacy=True`` opt-in returns the pre-QA-012 flat agent table for
one-release back-compat (the ``--legacy-board`` CLI flag); the helper
functions ``_render_header`` / ``_render_agent_table`` /
``_render_progress`` / ``_render_footer`` are kept module-private and
re-exported with explicit names so the panel modules can compose them
without forking the logic.
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

# Shared types live in ``ui/state.py`` (a leaf module) so the dashboard and
# the per-phase panels can import the same ``DashboardState`` without forming
# an import cycle. The names are re-exported here for back-compat with callers
# that historically imported them from ``ui.dashboard``.
from agent_guardian.ui.state import (
    AGENT_ROWS,
    AgentStatus,
    CurrentPhase,
    DashboardState,
    FindingRow,
    ReconSummary,
)

__all__ = [
    "AGENT_ROWS",
    "AgentStatus",
    "CurrentPhase",
    "DashboardState",
    "FindingRow",
    "ReconSummary",
    "make_dashboard",
]


_STATUS_STYLE: dict[AgentStatus, str] = {
    "pending": "status.pending",
    "running": "status.running",
    "done": "status.done",
    "error": "status.error",
    "skipped": "status.skipped",
}


def _aivss_style(provisional: int | None) -> str:
    """Pick an ``aivss.*`` theme token from the provisional score band."""
    if provisional is None:
        return "aivss.none"
    if provisional >= 80:
        return "aivss.high"
    if provisional >= 60:
        return "aivss.med"
    return "aivss.low"


def _render_header(state: DashboardState) -> Panel:
    """Top panel: scan_id, target_ref, tier, elapsed."""
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(no_wrap=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_row(Text("scan_id", style="brand.dim"), Text(state.scan_id))
    grid.add_row(Text("target", style="brand.dim"), Text(state.target_ref))
    grid.add_row(Text("tier", style="brand.dim"), Text(state.tier))
    grid.add_row(Text("elapsed", style="brand.dim"), Text(f"{state.elapsed_seconds:0.1f}s"))
    return Panel(grid, title="AgentGuardian — swarm board", border_style="brand")


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
        turn_str = f"{turn_pair[0]}/{turn_pair[1]}" if turn_pair else "—"
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


def _render_footer(state: DashboardState) -> Panel:
    """Bottom panel: provisional AIVSS + checkpoint decision."""
    aivss_text = "—" if state.provisional_aivss is None else str(state.provisional_aivss)
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(no_wrap=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_row(
        Text("provisional AIVSS", style="brand.dim"),
        Text(aivss_text, style=_aivss_style(state.provisional_aivss)),
    )
    grid.add_row(Text("decision", style="brand.dim"), Text(state.decision))
    return Panel(grid, border_style="brand.dim")


def _render_legacy(state: DashboardState) -> RenderableType:
    """Pre-QA-012 flat composition — kept for ``--legacy-board``.

    Identical to the pre-refactor :func:`make_dashboard` body:
    header → table → (optional) progress → footer.
    """
    parts: list[RenderableType] = [_render_header(state), _render_agent_table(state)]
    progress = _render_progress(state)
    if progress is not None:
        parts.append(progress)
    parts.append(_render_footer(state))
    return Group(*parts)


def make_dashboard(
    state: DashboardState,
    *,
    plan_panel: Panel | None = None,
    debug_feed: RenderableType | None = None,
    legacy: bool = False,
) -> RenderableType:
    """Build the swarm-board renderable from a :class:`DashboardState`.

    QA-012 composition order (top → bottom):

    1. (optional) ``plan_panel`` — the QA-011 Phase 0 panel. Rendered
       only while ``state.current_phase == "plan"``; once the swarm
       starts the composer drops it from later frames.
    2. Phase 1 — Recon panel.
    3. Phase 2 — Red Teaming panel.
    4. Phase 3 — Findings panel.
    5. (optional) ``debug_feed`` — QA-005's ``--debug`` attack feed
       renderable, placed BELOW Phase 3 (per QA-012 design lock).

    Pure — two calls with the same state produce equivalent
    renderables. The Plan-panel drop after ``current_phase`` advances
    is the load-bearing rule that keeps the QA-002 single-Live
    invariant intact.

    The ``legacy`` flag returns the pre-QA-012 flat agent table for one
    release of opt-in back-compat (the ``--legacy-board`` CLI flag).
    """
    if legacy:
        return _render_legacy(state)

    # Late imports so a broken panel module doesn't make ``dashboard``
    # untypeable on cold-start; the composer is forgiving.
    from agent_guardian.ui.findings_panel import build_findings_panel
    from agent_guardian.ui.recon_panel import build_recon_panel
    from agent_guardian.ui.red_team_panel import build_red_team_panel

    parts: list[RenderableType] = []
    if plan_panel is not None and state.current_phase == "plan":
        parts.append(plan_panel)
    parts.append(build_recon_panel(state))
    parts.append(build_red_team_panel(state))
    parts.append(build_findings_panel(state))
    if debug_feed is not None:
        parts.append(debug_feed)
    return Group(*parts)
