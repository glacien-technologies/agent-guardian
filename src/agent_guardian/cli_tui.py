"""Rich Live progress board for the AgentGuardian CLI (PRD §8.5, QA-002).

A single :class:`rich.live.Live` region owns stdout for the entire scan
lifetime. The Live's renderable is built fresh each tick from a
:class:`~agent_guardian.ui.dashboard.DashboardState` via
:func:`~agent_guardian.ui.dashboard.make_dashboard`, so there is exactly
one swarm-board panel on screen at any moment — the duplicate-frame
regression captured in the QA-002 reproducer cannot happen by
construction.

Logging is routed through ``rich.logging.RichHandler`` bound to the
*same* :class:`~rich.console.Console` this Live region owns (see
``agent_guardian.logging_setup.get_console``). That sharing is what
makes ``_LOG.info("hello")`` render ABOVE the Live frame as scrollback
rather than tearing the panel border.

For non-TTY targets (CI, ``stdout`` piped to a file, ``--no-tui``,
``NO_COLOR``) the caller skips the Live region entirely; the swarm
observer still fires, and the operator gets NDJSON via the existing
observer path.
"""

from __future__ import annotations

import contextlib
import time
from types import TracebackType

from rich.console import Console
from rich.live import Live

from agent_guardian.core.swarm import SwarmCommander, SwarmEvent
from agent_guardian.logging_setup import get_console
from agent_guardian.ui.dashboard import AGENT_ROWS, AgentStatus, DashboardState, make_dashboard

__all__ = ["ScanTUI"]


# Map SwarmEvent kinds to the state transitions on a row. Centralised so
# the event handler stays a thin shim and the table of behaviours is
# easy to audit.
_RECON_AGENT = "recon-agent"


class ScanTUI:
    """Async-friendly Live region for one swarm run (QA-002).

    Use as an async context manager. Call :meth:`attach_to` before
    entering — the TUI subscribes by wrapping the existing swarm
    observer so any caller-supplied observer keeps firing.
    """

    def __init__(
        self,
        scan_id: str,
        target_ref: str,
        tier: str,
        *,
        console: Console | None = None,
        refresh_per_second: int = 4,
    ) -> None:
        self.scan_id = scan_id
        self.target_ref = target_ref
        self.tier = tier
        self._console = console if console is not None else get_console()
        self._refresh_per_second = refresh_per_second
        self._state = DashboardState(
            scan_id=scan_id,
            target_ref=target_ref,
            tier=tier,
        )
        self._start: float = time.monotonic()
        self._live: Live | None = None

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
        self._state.elapsed_seconds = 0.0
        self._live = Live(
            make_dashboard(self._state),
            console=self._console,
            refresh_per_second=self._refresh_per_second,
            transient=False,
            vertical_overflow="visible",
        )
        self._live.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._live is not None:
            # One final render so the closing frame reflects the latest
            # state (e.g. final AIVSS) before Live restores the cursor.
            self._state.elapsed_seconds = time.monotonic() - self._start
            self._live.update(make_dashboard(self._state))
            self._live.stop()
            self._live = None

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def handle_event(self, event: SwarmEvent) -> None:
        """Update :class:`DashboardState` from one :class:`SwarmEvent`."""
        kind = event.kind
        agent = event.agent or ""
        new_status: AgentStatus | None = None

        if kind == "recon_start":
            self._state.agent_status[_RECON_AGENT] = "running"
        elif kind == "recon_done":
            self._state.agent_status[_RECON_AGENT] = "done"
        elif kind == "agent_start" and agent:
            self._state.agent_status[agent] = "running"
            new_status = "running"
        elif kind == "agent_progress" and agent:
            # Idempotent — agent_progress lets the swarm forward turn
            # counters (when available). Treat missing keys as no-op.
            turn = event.payload.get("turn") if isinstance(event.payload, dict) else None
            max_turns = event.payload.get("max_turns") if isinstance(event.payload, dict) else None
            if isinstance(turn, int) and isinstance(max_turns, int):
                self._state.agent_turns[agent] = (turn, max_turns)
        elif kind == "agent_done" and agent:
            self._state.agent_status[agent] = "done"
            findings = event.payload.get("findings_count") if event.payload else None
            if isinstance(findings, int):
                self._state.agent_findings[agent] = findings
            new_status = "done"
        elif kind == "agent_skipped" and agent:
            self._state.agent_status[agent] = "skipped"
            new_status = "skipped"
        elif kind == "checkpoint":
            if event.provisional_aivss is not None:
                self._state.provisional_aivss = event.provisional_aivss
            if event.decision is not None:
                self._state.decision = event.decision.value
            # Optional budget fields the checkpoint emitter may include.
            payload = event.payload if isinstance(event.payload, dict) else {}
            tokens_spent = payload.get("tokens_spent")
            tokens_cap = payload.get("tokens_cap")
            usd_spent = payload.get("usd_spent")
            usd_cap = payload.get("usd_cap")
            if isinstance(tokens_spent, int):
                self._state.budget_tokens_spent = tokens_spent
            if isinstance(tokens_cap, int):
                self._state.budget_tokens_cap = tokens_cap
            if isinstance(usd_spent, (int, float)):
                self._state.budget_usd_spent = float(usd_spent)
            if isinstance(usd_cap, (int, float)):
                self._state.budget_usd_cap = float(usd_cap)
        elif kind == "scan_done":
            if event.provisional_aivss is not None:
                self._state.provisional_aivss = event.provisional_aivss
            # Any agent still flagged running at scan-done is implicitly
            # complete (the swarm may not emit per-agent done in some
            # early-stop paths).
            for name, _ in AGENT_ROWS:
                if self._state.agent_status.get(name) == "running":
                    self._state.agent_status[name] = "done"

        # Mark unused locals as intentional; mypy --strict otherwise
        # warns about the unused ``new_status`` branches when the
        # caller chooses not to consume them yet (future-proofing).
        _ = new_status

        self._state.elapsed_seconds = time.monotonic() - self._start
        if self._live is not None:
            self._live.update(make_dashboard(self._state))
