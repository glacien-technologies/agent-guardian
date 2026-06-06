"""Shared state types for the swarm-board renderable (QA-002).

Lives in a leaf module so :mod:`agent_guardian.ui.dashboard` and the
per-phase panel modules (:mod:`agent_guardian.ui.recon_panel`,
:mod:`agent_guardian.ui.red_team_panel`,
:mod:`agent_guardian.ui.findings_panel`) can all import the same
:class:`DashboardState` / :class:`FindingRow` / :class:`ReconSummary`
without forming an import cycle.

The dashboard package historically defined :class:`DashboardState` inside
``dashboard.py`` and referenced :class:`FindingRow` / :class:`ReconSummary`
from the panel modules under ``TYPE_CHECKING``. Each panel in turn
referenced :class:`DashboardState` the same way. CodeQL flagged the
arrangement as an unsafe cyclic import; extracting the shared types to
this leaf module breaks the cycle by construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "AGENT_ROWS",
    "AgentStatus",
    "CurrentPhase",
    "DashboardState",
    "FindingRow",
    "PhaseStatus",
    "ReconSummary",
    "Severity",
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


# QA-012 — phase tracker. ``plan`` is the QA-011 prelude (before swarm
# start); ``recon`` / ``decompose`` / ``parallel`` / ``finalise`` mirror
# the engine phases; ``done`` is post-scan_done.
CurrentPhase = Literal["plan", "recon", "decompose", "parallel", "finalise", "done"]


PhaseStatus = Literal["pending", "running", "done", "skipped", "error"]


Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class FindingRow:
    """One row in the streaming findings panel.

    All fields are pre-redacted; the streaming list is built from the
    PII-safe summary the memory writer produced. Constructors that
    don't have a per-finding severity (the cli_tui projector when only
    a per-agent count is available) default to ``"high"`` so the row
    still surfaces in the most-visible severity group.
    """

    probe_id: str
    agent: str
    severity: Severity = "high"
    evidence: str = ""


@dataclass(frozen=True)
class ReconSummary:
    """Frozen snapshot of recon-phase output.

    Populated by the cli_tui ``handle_event`` branch for
    ``phase_done("recon")`` and read back by ``build_recon_panel``.
    All fields default to safe values so a half-populated summary still
    renders coherently.
    """

    goal: str = ""
    target_ref: str = ""
    # How many capability probes recon fired (audit-transcript length). This is
    # the number the recon panel surfaces — distinct from the phase-2 attack
    # probe applicability (``probes_applicable``), which recon does not compute.
    recon_probes: int = 0
    probes_applicable: int = 0
    probes_skipped: int = 0
    multi_agent: bool = False
    duration_seconds: float = 0.0
    status: PhaseStatus = "running"
    notes: str = ""


@dataclass
class DashboardState:
    """Single source-of-truth for the swarm board renderable (QA-002).

    Mutated by the swarm observer; consumed read-only by
    ``make_dashboard``. All numeric fields default to safe zeros
    so a fresh ``DashboardState(scan_id=..., target_ref=..., tier=...)``
    renders an immediately-valid empty board.

    QA-012 — additive fields for phase composition:

    * ``current_phase`` — drives panel collapse/expand decisions.
    * ``phase_durations`` — phase name → seconds; populated from
      ``phase_done`` events.
    * ``recon_summary`` — frozen recon snapshot; populated from
      ``phase_done("recon")``.
    * ``findings_streaming`` — append-only tuple of
      :class:`FindingRow`; the Findings panel rebuilds from it on
      each tick.
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
    # QA-012 — phase composition additions.
    current_phase: CurrentPhase = "plan"
    phase_durations: dict[str, float] = field(default_factory=dict)
    recon_summary: ReconSummary | None = None
    findings_streaming: tuple[FindingRow, ...] = ()
    # PhaseC — multi-turn plan label + attachment count per agent. Both
    # additive; absent keys render the legacy cell unchanged.
    agent_plan_label: dict[str, str] = field(default_factory=dict)
    agent_attachment_counts: dict[str, int] = field(default_factory=dict)
    # Live recon progress — capability-audit probes dispatched so far + the
    # current activity label. Populated from ``recon_progress`` events so the
    # Phase 1 panel shows motion during the (otherwise silent) audit.
    recon_probes_sent: int = 0
    recon_activity: str = ""

    def __post_init__(self) -> None:
        # Seed every known agent row with a "pending" status so the
        # initial render shows the full slate immediately. Subsequent
        # swarm events flip rows to running/done/error/skipped.
        for name, _ in AGENT_ROWS:
            self.agent_status.setdefault(name, "pending")
            self.agent_findings.setdefault(name, 0)
