"""Rich progress panel for the AgentGuardian CLI (PRD §8.5, M10).

A minimal terminal "swarm board" — one row per agent, header with scan
metadata, footer with the latest provisional AIVSS. Driven by
:class:`~agent_guardian.core.swarm.SwarmEvent` callbacks fired by the
:class:`~agent_guardian.core.swarm.SwarmCommander`.

M10 ships the simple version intentionally: a single Rich :class:`Live`
panel that refreshes a :class:`Table` on every event. The fancier
Textual-based TUI from PRD §8.5 (with per-agent progress bars and a
live findings sidebar) is deferred to v1.1. The current widget is
sufficient for "I want to watch the swarm work" and stays out of the
way when ``--no-tui`` is set.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterable
from types import TracebackType

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent_guardian.core.swarm import SwarmCommander, SwarmEvent

__all__ = ["ScanTUI"]


# Stable presentation order — matches PRD §3 + the recon agent at the top.
_AGENT_ROWS: tuple[tuple[str, str], ...] = (
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


_STATUS_COLOURS: dict[str, str] = {
    "waiting": "dim white",
    "running": "yellow",
    "done": "green",
    "skipped": "dim cyan",
    "error": "red",
}


class ScanTUI:
    """Async-friendly progress board for one swarm run.

    Use as an async context manager. Call :meth:`attach_to` before
    entering — the TUI subscribes by wrapping the existing swarm
    observer so any caller-supplied observer keeps firing.
    """

    def __init__(self, scan_id: str, target_ref: str, tier: str) -> None:
        self.scan_id = scan_id
        self.target_ref = target_ref
        self.tier = tier
        self._statuses: dict[str, str] = {name: "waiting" for name, _ in _AGENT_ROWS}
        self._findings: dict[str, int] = {name: 0 for name, _ in _AGENT_ROWS}
        self._provisional_aivss: int | None = None
        self._decision: str = "—"
        self._start: float = time.monotonic()
        self._live: Live | None = None
        self._console = Console()

    # ------------------------------------------------------------------
    # Attachment + lifecycle
    # ------------------------------------------------------------------

    def attach_to(self, swarm: SwarmCommander) -> None:
        """Wire the TUI into a :class:`SwarmCommander`'s observer slot."""
        prior_observer = swarm.observer

        def _observer(event: SwarmEvent) -> None:
            self.handle_event(event)
            if prior_observer is not None:
                # Observers must never crash the swarm.
                with contextlib.suppress(Exception):
                    prior_observer(event)

        swarm.observer = _observer

    async def __aenter__(self) -> ScanTUI:
        self._start = time.monotonic()
        self._live = Live(self._render(), console=self._console, refresh_per_second=4)
        self._live.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._live is not None:
            self._live.update(self._render())
            self._live.stop()
            self._live = None

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def handle_event(self, event: SwarmEvent) -> None:
        """Update internal state from one :class:`SwarmEvent`."""
        kind = event.kind
        agent = event.agent or ""
        if kind == "recon_start":
            self._statuses["recon-agent"] = "running"
        elif kind == "recon_done":
            self._statuses["recon-agent"] = "done"
        elif kind == "agent_start" and agent:
            self._statuses[agent] = "running"
        elif kind == "agent_done" and agent:
            self._statuses[agent] = "done"
            findings = event.payload.get("findings_count")
            if isinstance(findings, int):
                self._findings[agent] = findings
        elif kind == "agent_skipped" and agent:
            self._statuses[agent] = "skipped"
        elif kind == "checkpoint":
            if event.provisional_aivss is not None:
                self._provisional_aivss = event.provisional_aivss
            if event.decision is not None:
                self._decision = event.decision.value
        elif kind == "scan_done":
            if event.provisional_aivss is not None:
                self._provisional_aivss = event.provisional_aivss
            for name in list(self._statuses.keys()):
                if self._statuses[name] == "running":
                    self._statuses[name] = "done"

        if self._live is not None:
            self._live.update(self._render())

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self) -> Panel:
        elapsed = time.monotonic() - self._start
        table = Table(expand=True, show_lines=False, padding=(0, 1))
        table.add_column("Agent", no_wrap=True)
        table.add_column("ASI", justify="center", no_wrap=True)
        table.add_column("Status", justify="left", no_wrap=True)
        table.add_column("Findings", justify="right", no_wrap=True)

        for name, asi in _AGENT_ROWS:
            status = self._statuses.get(name, "waiting")
            colour = _STATUS_COLOURS.get(status, "white")
            table.add_row(
                name,
                asi,
                Text(status, style=colour),
                str(self._findings.get(name, 0)),
            )

        provisional = "—" if self._provisional_aivss is None else str(self._provisional_aivss)
        header_lines: Iterable[str] = (
            f"scan_id: {self.scan_id}",
            f"target:  {self.target_ref}",
            f"tier:    {self.tier}",
            f"elapsed: {elapsed:0.1f}s",
        )
        header = Text("\n".join(header_lines), style="bold")
        footer = Text(
            f"provisional AIVSS: {provisional}   decision: {self._decision}",
            style="bold magenta",
        )
        body = Table.grid(expand=True)
        body.add_row(header)
        body.add_row(table)
        body.add_row(footer)
        return Panel(body, title="AgentGuardian — swarm board", border_style="cyan")
