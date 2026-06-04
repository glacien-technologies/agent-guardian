"""QA-012 Phase 2 panel — Red Teaming.

Reuses the today's flat agent table + budget bars + footer helpers from
:mod:`agent_guardian.ui.dashboard` (kept private to that module and
imported through their public-prefixed wrappers here). The panel
renders three different shapes depending on
``state.current_phase``:

* ``plan`` / ``recon`` / ``decompose`` → "queued" placeholder so the
  operator sees the phase exists before recon completes;
* ``parallel`` → full agent table (rebadged with Turns + Findings
  columns, budget bar, elapsed) — the load-bearing red-team frame;
* ``finalise`` / ``done`` → collapsed single-line summary so the
  Findings panel owns the visual focus while the red-team result is
  still discoverable.

The renderer is pure — same state in → equivalent Panel out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# Pulled from a neutral leaf module (``ui._panel_render``) rather than
# ``ui.dashboard`` so the static import graph stays acyclic — see the
# module docstring on ``_panel_render`` for the CodeQL background.
from agent_guardian.ui._panel_render import _render_agent_table
from agent_guardian.ui.state import AGENT_ROWS

if TYPE_CHECKING:
    from agent_guardian.ui.state import DashboardState

__all__ = ["build_red_team_panel"]


def _format_duration(seconds: float) -> str:
    if seconds < 60.0:
        return f"{seconds:.1f}s"
    mins = int(seconds // 60)
    secs = int(seconds - mins * 60)
    return f"{mins}m {secs:02d}s"


def _queued_panel() -> Panel:
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(no_wrap=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_row(Text("status", style="brand.dim"), Text("○ queued", style="status.pending"))
    grid.add_row(
        Text("note", style="brand.dim"),
        Text(
            "waiting on reconnaissance to complete",
            style="status.pending",
        ),
    )
    return Panel(
        grid,
        title="Phase 2 · Red Teaming",
        border_style="status.pending",
    )


def _running_summary_panel(state: DashboardState) -> Panel:
    """Compact, single-line progress while red teaming runs.

    QA-074 — during the run we keep the Phase 2 panel THIN (a spinner + live
    counts) instead of the full agent table. The constantly-redrawing 11-row
    table fought with the per-probe verdict log lines scrolling above it and was
    hard to read. The full per-agent table renders once red teaming COMPLETES
    (see :func:`_done_table_panel`); until then the scrollback verdict feed is
    the live detail and this line is just the heartbeat.
    """
    specialists = [name for name, _ in AGENT_ROWS if name != "recon-agent"]
    total = len(specialists)
    done = sum(1 for n in specialists if state.agent_status.get(n) == "done")
    running = sum(1 for n in specialists if state.agent_status.get(n) == "running")
    findings = sum(c for name, c in state.agent_findings.items() if name != "recon-agent")
    label = Text()
    label.append(f" {done}/{total} agents done", style="status.running")
    if running:
        label.append(f" · {running} attacking", style="brand.dim")
    label.append(" · ", style="brand.dim")
    label.append(f"{findings} findings", style="sev.high" if findings else "brand.dim")
    label.append(f" · {_format_duration(state.elapsed_seconds)}", style="brand.dim")
    cap = state.budget_usd_cap
    spent = state.budget_usd_spent
    if cap is not None and cap > 0:
        pct = int(min(100, (spent / cap) * 100))
        label.append(f" · budget {pct}%", style="brand.dim")
    spinner = Spinner("dots", text=label, style="status.running")
    return Panel(
        spinner,
        title="Phase 2 · Red Teaming",
        border_style="status.running",
        padding=(0, 1),
    )


def _done_table_panel(state: DashboardState) -> Panel:
    """Full per-agent table — shown once red teaming COMPLETES, so the operator
    reads a stable final status (not a table redrawing under the live feed)."""
    # QA-049 — column legend. Without this hint operators read a
    # "Findings: 0 / Status: done" row on the recon-agent (or any
    # skipped-mode agent) as "the test failed silently"; in reality
    # recon-class agents never produce findings by design.
    legend = Text.assemble(
        ("legend  ", "brand.dim"),
        ("Findings", "bold"),
        (" = security issues surfaced by the agent · ", "brand.dim"),
        ("Turns", "bold"),
        (" = attack turns issued / max · ", "brand.dim"),
        ("recon-class agents (recon-agent, a2a-agent in skipped mode) ", "brand.dim"),
        ("never produce findings by design", "brand.dim"),
        (".", "brand.dim"),
    )
    parts: list[RenderableType] = [legend, _render_agent_table(state)]
    body: RenderableType = Group(*parts)
    duration = state.phase_durations.get(
        "parallel", state.elapsed_seconds - state.phase_durations.get("recon", 0.0)
    )
    findings = sum(c for name, c in state.agent_findings.items() if name != "recon-agent")
    title = f"Phase 2 · Red Teaming · ✓ done ({_format_duration(duration)}) · {findings} findings"
    return Panel(body, title=title, border_style="status.done")


def build_red_team_panel(state: DashboardState) -> Panel:
    """Return the Phase 2 panel for the given dashboard state.

    QA-074 layout — dispatch by ``state.current_phase``:

    * ``plan`` / ``recon`` / ``decompose`` → queued placeholder.
    * ``parallel`` → THIN running summary (spinner + live counts). The full
      table is intentionally withheld here so the per-probe verdict log lines
      scrolling above stay readable.
    * ``finalise`` / ``done`` → the full per-agent table (stable final status).
    """
    phase = state.current_phase
    if phase in {"plan", "recon", "decompose"}:
        return _queued_panel()
    if phase in {"finalise", "done"}:
        return _done_table_panel(state)
    return _running_summary_panel(state)
