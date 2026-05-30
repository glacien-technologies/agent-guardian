"""Rich Live-region renderable for the AgentGuardian scan TUI (QA-002).

This module owns the *single source of truth* for what the scrollback
shows during a scan: a :class:`rich.console.Group` composed of header
panel, agent table, optional budget progress bars, and footer panel.

The renderer is **pure** — :func:`make_dashboard` is side-effect free
and only consumes a :class:`DashboardState`. Callers update the state
and pass it to ``Live.update(make_dashboard(state))`` each tick. This
keeps the smoking-gun race the old TUI had (a ``console.print(panel)``
per event accumulating duplicate frames in scrollback) impossible by
construction — there is exactly one renderable at any moment and Rich
re-paints it in place.

Color tokens are sourced from ``agent_guardian.logging_setup._AG_THEME``;
this module does **not** hard-code any ANSI sequences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

__all__ = [
    "AGENT_ROWS",
    "DashboardState",
    "make_dashboard",
]


# Stable presentation order — recon row first, then ASI01..ASI10.
# This is the v1.0 single-tier slate; richer per-agent metadata
# (current_turn/max_turns) is not yet on SwarmEvent so we keep the
# row set static and rely on status pills + findings counts.
AGENT_ROWS: tuple[tuple[str, str], ...] = (
    ("recon-agent", "n/a"),
    ("goal-hijack-agent", "ASI01"),
    ("tool-abuse-agent", "ASI02"),
    ("privilege-agent", "ASI03"),
    ("supply-chain-agent", "ASI04"),
    ("code-exec-agent", "ASI05"),
    ("memory-poison-agent", "ASI06"),
    ("a2a-agent", "ASI07"),
    ("cascade-agent", "ASI08"),
    ("trust-exploit-agent", "ASI09"),
    ("drift-agent", "ASI10"),
)


AgentStatus = Literal["pending", "running", "done", "error", "skipped"]


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


@dataclass
class DashboardState:
    """Single source-of-truth for the swarm board renderable (QA-002).

    Mutated by the swarm observer; consumed read-only by
    :func:`make_dashboard`. All numeric fields default to safe zeros
    so a fresh ``DashboardState(scan_id=..., target_ref=..., tier=...)``
    renders an immediately-valid empty board.
    """

    scan_id: str
    target_ref: str
    tier: str
    elapsed_seconds: float = 0.0
    agent_status: dict[str, AgentStatus] = field(default_factory=dict)
    agent_findings: dict[str, int] = field(default_factory=dict)
    agent_turns: dict[str, tuple[int, int]] = field(default_factory=dict)
    provisional_aivss: int | None = None
    decision: str = "—"
    budget_tokens_spent: int = 0
    budget_tokens_cap: int | None = None
    budget_usd_spent: float = 0.0
    budget_usd_cap: float | None = None

    def __post_init__(self) -> None:
        # Seed every known agent row with a "pending" status so the
        # initial render shows the full slate immediately. Subsequent
        # swarm events flip rows to running/done/error/skipped.
        for name, _ in AGENT_ROWS:
            self.agent_status.setdefault(name, "pending")
            self.agent_findings.setdefault(name, 0)


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


def make_dashboard(state: DashboardState) -> RenderableType:
    """Build the swarm-board renderable from a :class:`DashboardState`.

    Returns a :class:`rich.console.Group` containing — in order —
    the header panel, the agent table, an optional budget
    :class:`rich.progress.Progress` (omitted when no caps set), and
    the footer panel. The function is pure: two calls with the same
    state produce equivalent renderables.
    """
    parts: list[RenderableType] = [_render_header(state), _render_agent_table(state)]
    progress = _render_progress(state)
    if progress is not None:
        parts.append(progress)
    parts.append(_render_footer(state))
    return Group(*parts)
