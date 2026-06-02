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

QA-012 — the TUI accepts ``phase_start`` / ``phase_done`` events from
the engine and projects them onto ``DashboardState.current_phase``,
``state.phase_durations``, and ``state.recon_summary``. Each
``agent_done`` with ``findings_count > 0`` also lands an entry in
``state.findings_streaming`` so the Phase 3 Findings panel updates
live (not just at scan-end).
"""

from __future__ import annotations

import contextlib
import logging
import time
from types import TracebackType
from typing import Any

from rich.console import Console, RenderableType
from rich.live import Live
from rich.panel import Panel

from agent_guardian.core.swarm import SwarmCommander, SwarmEvent
from agent_guardian.logging_setup import get_console
from agent_guardian.ui.dashboard import (
    AGENT_ROWS,
    AgentStatus,
    CurrentPhase,
    DashboardState,
    make_dashboard,
)
from agent_guardian.ui.findings_panel import FindingRow, Severity
from agent_guardian.ui.recon_panel import ReconSummary

__all__ = ["ScanTUI"]

_LOG = logging.getLogger(__name__)


# Map SwarmEvent kinds to the state transitions on a row. Centralised so
# the event handler stays a thin shim and the table of behaviours is
# easy to audit.
_RECON_AGENT = "recon-agent"


# QA-012 — phase ordering used by ``_next_phase_after`` to advance
# ``state.current_phase`` between ``phase_done`` and the next
# ``phase_start``. ``done`` is a terminal pseudo-phase the composer
# treats like ``finalise`` for collapse decisions.
_PHASE_ORDER: tuple[str, ...] = ("recon", "decompose", "parallel", "finalise", "done")


def _next_phase_after(phase: str) -> CurrentPhase:
    """Return the next phase in the engine ordering, or ``"done"`` if last."""
    try:
        idx = _PHASE_ORDER.index(phase)
    except ValueError:
        return "done"
    if idx + 1 >= len(_PHASE_ORDER):
        return "done"
    return _PHASE_ORDER[idx + 1]  # type: ignore[return-value]


# Heuristic mapping from agent name to most-likely finding severity
# when the engine only reports a per-agent finding count (not per-finding
# severity). HIGH covers the common case where an attacker agent files
# a successful prompt-injection; the projection prefers the highest
# severity that's consistent with the engine's output. This keeps the
# panel honest (no random colour) while not requiring a per-finding
# sidecar feed.
_DEFAULT_SEVERITY: Severity = "high"


class ScanTUI:
    """Async-friendly Live region for one swarm run (QA-002).

    Use as an async context manager. Call :meth:`attach_to` before
    entering — the TUI subscribes by wrapping the existing swarm
    observer so any caller-supplied observer keeps firing.

    QA-012 — accepts an optional ``plan_panel`` (the QA-011 Phase 0
    panel) and an optional ``debug_feed`` renderable; both compose
    into the same Group as the three phase panels. ``legacy_board=True``
    bypasses the composer and renders the pre-QA-012 flat agent table.
    """

    def __init__(
        self,
        scan_id: str,
        target_ref: str,
        tier: str,
        *,
        console: Console | None = None,
        refresh_per_second: int = 4,
        plan_panel: Panel | None = None,
        debug_feed: RenderableType | None = None,
        legacy_board: bool = False,
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
        # QA-012 — composition extras.
        self._plan_panel = plan_panel
        self._debug_feed = debug_feed
        self._legacy_board = legacy_board

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

    def _render(self) -> RenderableType:
        return make_dashboard(
            self._state,
            plan_panel=self._plan_panel,
            debug_feed=self._debug_feed,
            legacy=self._legacy_board,
        )

    async def __aenter__(self) -> ScanTUI:
        self._start = time.monotonic()
        self._state.elapsed_seconds = 0.0
        self._live = Live(
            self._render(),
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
            self._live.update(self._render())
            self._live.stop()
            self._live = None

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def _apply_phase_start(self, payload: dict[str, Any]) -> None:
        phase = payload.get("phase")
        if not isinstance(phase, str):  # pragma: no cover -- defensive
            return
        if phase in _PHASE_ORDER:
            self._state.current_phase = phase  # type: ignore[assignment]
            self._state.phase_durations.setdefault(phase, 0.0)

    def _apply_phase_done(self, payload: dict[str, Any]) -> None:
        phase = payload.get("phase")
        if not isinstance(phase, str):  # pragma: no cover -- defensive
            return
        duration = payload.get("duration_seconds")
        if isinstance(duration, (int, float)):
            self._state.phase_durations[phase] = float(duration)
        summary = payload.get("summary")
        if phase == "recon" and isinstance(summary, dict):
            self._state.recon_summary = ReconSummary(
                goal=str(summary.get("inferred_goal", "")),
                target_ref=self._state.target_ref,
                probes_applicable=int(summary.get("probes_applicable", 0) or 0),
                probes_skipped=int(summary.get("probes_skipped", 0) or 0),
                multi_agent=bool(summary.get("multi_agent", False)),
                duration_seconds=float(duration or 0.0),
                status="done",
                notes=str(summary.get("notes", "")),
            )
        # Advance the phase counter into the next pending phase until
        # the next phase_start arrives. ``finalise`` done → ``"done"``.
        self._state.current_phase = _next_phase_after(phase)

    def _project_findings(self, agent: str, findings_count: int) -> None:
        """Append placeholder rows for a per-agent finding count.

        The engine's ``agent_done`` event only carries a finding count,
        not per-finding severity. We project one row per finding so the
        Findings panel updates live; the row's evidence is left blank
        (the operator has the full transcript via ``--debug`` or the
        dashboard's reflection feed).
        """
        if findings_count <= 0:
            return
        rows = list(self._state.findings_streaming)
        for i in range(findings_count):
            rows.append(
                FindingRow(
                    probe_id=f"{agent}-{len(rows) + i + 1:03d}",
                    agent=agent,
                    severity=_DEFAULT_SEVERITY,
                    evidence="see report for evidence",
                )
            )
        self._state.findings_streaming = tuple(rows)

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
            payload = event.payload if isinstance(event.payload, dict) else {}
            turn = payload.get("turn")
            max_turns = payload.get("max_turns")
            if isinstance(turn, int) and isinstance(max_turns, int):
                self._state.agent_turns[agent] = (turn, max_turns)
            # PhaseC — multi-turn plan label + per-turn attachment count.
            # Both keys are optional; absent payload keys leave state alone.
            plan_name = payload.get("plan_name")
            if isinstance(plan_name, str) and plan_name.strip():
                self._state.agent_plan_label[agent] = plan_name.strip()
            attachments_count = payload.get("attachments_count")
            if isinstance(attachments_count, int) and attachments_count >= 0:
                self._state.agent_attachment_counts[agent] = attachments_count
        elif kind == "agent_done" and agent:
            self._state.agent_status[agent] = "done"
            findings = event.payload.get("findings_count") if event.payload else None
            if isinstance(findings, int):
                self._state.agent_findings[agent] = findings
                self._project_findings(agent, findings)
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
        elif kind == "phase_start":
            payload = event.payload if isinstance(event.payload, dict) else {}
            self._apply_phase_start(payload)
        elif kind == "phase_done":
            payload = event.payload if isinstance(event.payload, dict) else {}
            self._apply_phase_done(payload)

        # Mark unused locals as intentional; mypy --strict otherwise
        # warns about the unused ``new_status`` branches when the
        # caller chooses not to consume them yet (future-proofing).
        _ = new_status

        self._state.elapsed_seconds = time.monotonic() - self._start
        if self._live is not None:
            self._live.update(self._render())
