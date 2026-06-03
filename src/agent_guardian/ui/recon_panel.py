"""QA-012 Phase 1 panel — Reconnaissance.

A pure renderer over :class:`DashboardState`. The composer in
:mod:`agent_guardian.ui.dashboard` calls :func:`build_recon_panel` once
per tick and lets the panel pick its own representation:

* ``state.recon_summary is None`` → "pending" / "running" hint.
* recon active but not yet done → "running" status pill + elapsed.
* recon done, current phase still <= recon → full fact-sheet.
* recon done, current phase past recon (collapsed) → single-line
  summary so later phases own the visual focus while the recon record
  remains visible to the operator.

The renderer is pure — same state in → equivalent Panel out — so the
QA-002 "exactly one Live frame" invariant is trivially preserved.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Shared types live in the leaf module ``ui/state.py`` — this used to be a
# cyclic import via ``ui.dashboard`` (DashboardState referenced ReconSummary,
# ReconSummary lived here, this module referenced DashboardState).
from agent_guardian.ui.state import PhaseStatus, ReconSummary

if TYPE_CHECKING:
    from agent_guardian.ui.state import DashboardState

__all__ = ["PhaseStatus", "ReconSummary", "build_recon_panel"]


_STATUS_GLYPH: dict[PhaseStatus, str] = {
    "pending": "○ pending",
    "running": "◐ running",
    "done": "✓ done",
    "skipped": "⏭ skipped",
    "error": "✗ error",
}


_STATUS_STYLE: dict[PhaseStatus, str] = {
    "pending": "status.pending",
    "running": "status.running",
    "done": "status.done",
    "skipped": "status.skipped",
    "error": "status.error",
}


def _status_text(status: PhaseStatus) -> Text:
    return Text(_STATUS_GLYPH[status], style=_STATUS_STYLE[status])


def _format_duration(seconds: float) -> str:
    if seconds <= 0.0:
        return "0s"
    if seconds < 60.0:
        return f"{seconds:.1f}s"
    mins = int(seconds // 60)
    secs = int(seconds - mins * 60)
    return f"{mins}m {secs:02d}s"


def _pending_panel(target_ref: str) -> Panel:
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(no_wrap=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_row(Text("status", style="brand.dim"), _status_text("pending"))
    grid.add_row(
        Text("target", style="brand.dim"),
        Text(target_ref or "—", style="status.pending"),
    )
    grid.add_row(
        Text("note", style="brand.dim"),
        Text("waiting on swarm start", style="status.pending"),
    )
    return Panel(
        grid,
        title="Phase 1 · Reconnaissance",
        border_style="status.pending",
    )


def _collapsed_panel(summary: ReconSummary) -> Panel:
    """Single-line summary for completed recon when later phases own focus."""
    line = Text.assemble(
        ("Phase 1 · Reconnaissance ", "brand.dim"),
        (_STATUS_GLYPH[summary.status] + " ", _STATUS_STYLE[summary.status]),
        (f"({_format_duration(summary.duration_seconds)})", "brand.dim"),
        " · ",
        (f"{summary.probes_applicable} probes apply", "status.done"),
        (f" · {summary.probes_skipped} skipped", "brand.dim")
        if summary.probes_skipped
        else ("", ""),
        (" · multi-agent" if summary.multi_agent else "", "brand.dim"),
    )
    return Panel(line, border_style="brand.dim", padding=(0, 1))


def _full_panel(summary: ReconSummary, *, elapsed: float | None) -> Panel:
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(no_wrap=True)
    grid.add_column(justify="left", ratio=1)
    goal_text = summary.goal or "(no operator goal — using inferred)"
    grid.add_row(Text("goal", style="brand.dim"), Text(goal_text))
    grid.add_row(Text("target", style="brand.dim"), Text(summary.target_ref or "—"))
    multi = "yes" if summary.multi_agent else "no"
    what_we_found = (
        f"{summary.probes_applicable} probes apply · "
        f"{summary.probes_skipped} skipped · multi-agent: {multi}"
    )
    grid.add_row(Text("what we found", style="brand.dim"), Text(what_we_found))
    if summary.notes:
        grid.add_row(Text("notes", style="brand.dim"), Text(summary.notes))
    status_text = _status_text(summary.status)
    if summary.status == "running" and elapsed is not None:
        status_text.append(f" ({_format_duration(elapsed)})", style="brand.dim")
    elif summary.status == "done":
        status_text.append(f" ({_format_duration(summary.duration_seconds)})", style="brand.dim")
    grid.add_row(Text("status", style="brand.dim"), status_text)
    border = (
        "status.done"
        if summary.status == "done"
        else "status.running"
        if summary.status == "running"
        else "brand"
    )
    return Panel(grid, title="Phase 1 · Reconnaissance", border_style=border)


def build_recon_panel(state: DashboardState) -> Panel:
    """Return the Phase 1 panel for the given dashboard state.

    Dispatches between three shapes based on
    ``state.recon_summary`` and ``state.current_phase``:

    * no summary, current phase pending/recon → "pending" panel.
    * summary present, current phase still in {plan,recon,decompose}
      → full fact-sheet (status pill + duration + what-we-found).
    * summary present, current phase advanced past decompose
      → collapsed single-line summary.
    """
    summary = state.recon_summary
    if summary is None:
        return _pending_panel(state.target_ref)
    collapsed = state.current_phase in {"parallel", "finalise", "done"}
    if collapsed:
        return _collapsed_panel(summary)
    elapsed = state.phase_durations.get("recon", state.elapsed_seconds)
    return _full_panel(summary, elapsed=elapsed)
