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
from rich.table import Table
from rich.text import Text

# Pulled from a neutral leaf module (``ui._panel_render``) rather than
# ``ui.dashboard`` so the static import graph stays acyclic — see the
# module docstring on ``_panel_render`` for the CodeQL background.
from agent_guardian.ui._panel_render import _render_agent_table, _render_progress
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


def _collapsed_panel(state: DashboardState) -> Panel:
    """Single-line summary when Phase 3 (Findings) owns the focus."""
    n_done = sum(
        1
        for name, _ in AGENT_ROWS
        if name != "recon-agent" and state.agent_status.get(name) == "done"
    )
    n_findings = sum(count for name, count in state.agent_findings.items() if name != "recon-agent")
    duration = state.phase_durations.get(
        "parallel", state.elapsed_seconds - state.phase_durations.get("recon", 0.0)
    )
    line = Text.assemble(
        ("Phase 2 · Red Teaming ", "brand.dim"),
        ("✓ done ", "status.done"),
        (f"({_format_duration(duration)})", "brand.dim"),
        " · ",
        (f"{n_done} agents", "status.done"),
        " · ",
        (f"{n_findings} findings", "sev.high" if n_findings else "brand.dim"),
    )
    return Panel(line, border_style="brand.dim", padding=(0, 1))


def _active_title(state: DashboardState) -> str:
    elapsed = state.elapsed_seconds
    title = f"Phase 2 · Red Teaming · {_format_duration(elapsed)} elapsed"
    cap = state.budget_usd_cap
    spent = state.budget_usd_spent
    if cap is not None and cap > 0:
        pct = int(min(100, (spent / cap) * 100))
        title += f" · budget {pct}% (${spent:.4f}/${cap:.4f})"
    return title


def _active_panel(state: DashboardState) -> Panel:
    # QA-049 — column legend. Without this hint operators read a
    # "Findings: 0 / Status: done" row on the recon-agent (or any
    # skipped-mode agent) as "the test failed silently"; in reality
    # recon-class agents never produce findings by design. Spelling
    # out what the Findings column actually counts disambiguates the
    # "0 findings while status=done" surface.
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
    # Render helpers come from the neutral ``_panel_render`` leaf module,
    # so this module no longer has any static or runtime dependency on
    # ``ui.dashboard`` — the CodeQL-flagged static import cycle is gone.
    parts: list[RenderableType] = [legend, _render_agent_table(state)]
    progress = _render_progress(state)
    if progress is not None:
        parts.append(progress)
    body: RenderableType = Group(*parts)
    return Panel(
        body,
        title=_active_title(state),
        border_style="status.running",
    )


def build_red_team_panel(state: DashboardState) -> Panel:
    """Return the Phase 2 panel for the given dashboard state.

    Dispatches between queued / active / collapsed presentations based
    on ``state.current_phase``:

    * ``plan`` / ``recon`` / ``decompose`` → queued placeholder.
    * ``parallel`` → today's agent table inside a phase panel.
    * ``finalise`` / ``done`` → single-line collapsed summary.
    """
    phase = state.current_phase
    if phase in {"plan", "recon", "decompose"}:
        return _queued_panel()
    if phase in {"finalise", "done"}:
        return _collapsed_panel(state)
    return _active_panel(state)
