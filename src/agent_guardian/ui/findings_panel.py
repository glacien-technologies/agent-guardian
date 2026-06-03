"""QA-012 Phase 3 panel — Findings.

Streaming severity-grouped list of every finding the swarm has produced
so far. The renderer is pure over ``DashboardState.findings_streaming``
and ``DashboardState.current_phase`` — the cli_tui ``handle_event``
branch projects each ``agent_done`` event with ``findings_count > 0``
into ``FindingRow`` entries; this module owns the visual layout.

Ordering invariant (locked by §3 L04 of the design lock):

    CRITICAL → HIGH → MEDIUM → LOW → INFO

Within a severity group, rows render in arrival order (the order they
landed in ``DashboardState.findings_streaming``). Each row is:

    <icon> <probe_id> · <agent> · <one-line evidence>

The empty state shows a placeholder line so the panel never collapses
to a blank Group — that would make the layout shift on first finding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Shared types live in the leaf module ``ui/state.py`` — this used to be a
# cyclic import via ``ui.dashboard`` (DashboardState referenced FindingRow,
# FindingRow lived here, this module referenced DashboardState).
from agent_guardian.ui.state import FindingRow, Severity

if TYPE_CHECKING:
    from agent_guardian.ui.state import DashboardState

__all__ = ["FindingRow", "Severity", "build_findings_panel"]


# Locked ordering — design lock §3 L04. CRITICAL first so the operator's
# eye lands on the highest-severity rows before scanning down.
_SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")


_SEVERITY_LABEL: dict[Severity, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


_SEVERITY_STYLE: dict[Severity, str] = {
    "critical": "sev.critical",
    "high": "sev.high",
    "medium": "sev.med",
    "low": "sev.low",
    "info": "status.pending",
}


_SEVERITY_GLYPH: dict[Severity, str] = {
    "critical": "✗",
    "high": "✗",
    "medium": "⚠",
    "low": "⚠",
    "info": "ℹ",  # noqa: RUF001 - INFORMATION SOURCE glyph is intentional
}


def _truncate(line: str, *, limit: int = 80) -> str:
    if len(line) <= limit:
        return line
    return line[: limit - 1] + "…"


def _header_text(rows: tuple[FindingRow, ...]) -> Text:
    totals: dict[Severity, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    for row in rows:
        totals[row.severity] = totals.get(row.severity, 0) + 1
    summary = Text.assemble(
        (f"{len(rows)} total", "status.done" if rows else "brand.dim"),
        " · ",
        (f"{totals['critical']} critical", _SEVERITY_STYLE["critical"]),
        " · ",
        (f"{totals['high']} high", _SEVERITY_STYLE["high"]),
        " · ",
        (f"{totals['medium']} medium", _SEVERITY_STYLE["medium"]),
        " · ",
        (f"{totals['low']} low", _SEVERITY_STYLE["low"]),
    )
    return summary


def _empty_body() -> Text:
    return Text(
        "Findings will appear here as red-team agents complete.",
        style="status.pending",
    )


def _group_body(rows: tuple[FindingRow, ...]) -> RenderableType:
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(no_wrap=True)
    by_severity: dict[Severity, list[FindingRow]] = {sev: [] for sev in _SEVERITY_ORDER}
    for row in rows:
        if row.severity in by_severity:
            by_severity[row.severity].append(row)
        else:  # pragma: no cover -- defensive
            by_severity["info"].append(row)
    parts: list[RenderableType] = []
    for sev in _SEVERITY_ORDER:
        bucket = by_severity[sev]
        if not bucket:
            continue
        # Severity-group label so the operator's eye groups by severity.
        parts.append(Text(_SEVERITY_LABEL[sev], style=_SEVERITY_STYLE[sev]))
        bucket_grid = Table.grid(padding=(0, 1), expand=True)
        bucket_grid.add_column(no_wrap=True)
        for row in bucket:
            line = Text.assemble(
                (f"{_SEVERITY_GLYPH[sev]} ", _SEVERITY_STYLE[sev]),
                (row.probe_id, _SEVERITY_STYLE[sev]),
                " · ",
                (row.agent, "brand.dim"),
                " · ",
                (_truncate(row.evidence or ""), "status.pending"),
            )
            bucket_grid.add_row(line)
        parts.append(bucket_grid)
    return Group(*parts)


def build_findings_panel(state: DashboardState) -> Panel:
    """Return the Phase 3 panel for the given dashboard state.

    Empty input renders a placeholder; any populated stream renders a
    severity-grouped list. Title carries the totals so the operator
    sees the breakdown at a glance even when the body scrolls past
    the first screen.
    """
    rows = state.findings_streaming
    body: RenderableType = _empty_body() if not rows else _group_body(rows)
    title = Text.assemble(
        ("Phase 3 · Findings", "brand"),
        " · ",
        _header_text(rows),
    )
    border = "status.running" if rows else "status.pending"
    return Panel(body, title=title, border_style=border)
