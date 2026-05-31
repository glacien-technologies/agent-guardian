"""Scan-plan panel — Phase 0 of the QA-012 four-phase narrative (QA-011).

A pure-function builder takes a fully-validated :class:`ScanPlanContext`
and returns a :class:`rich.panel.Panel` ready to be passed to
``console.print`` or used as one renderable inside a
:class:`rich.console.Group` (QA-012 Phase 0).

The CLI handles the wait-loop (Enter to proceed, 5 s default
auto-proceed, ``--yes`` / non-TTY / ``$CI`` / env-override skip). This
module owns only the rendering — pure, deterministic, no I/O.

Locked layout (DESIGN_LOCK §3 L01):

* 7 row sections in fixed order: TARGET, MODELS, BUDGET, OUTPUTS,
  DASHBOARD, SAFETY GUARDS, WARNINGS.
* Status pills are sourced from ctx field values; the builder NEVER
  re-runs probes. The caller is responsible for collecting probe
  results into :class:`ScanPlanContext` before calling
  :func:`build_plan_panel`.
* WARNINGS section is omitted when ``ctx.warnings`` is empty.
* Pill glyphs: ``✓`` (ok), ``✗`` (fail), ``⚠`` (warn / suppression),
  ``·`` (info / neutral).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from rich import box
from rich.console import Group
from rich.markup import escape as _rich_escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent_guardian.llm.validation import ModelValidationResult
from agent_guardian.reports.output_engines import EngineCheck

__all__ = [
    "BudgetRow",
    "DashboardRow",
    "ModelRow",
    "OutputRow",
    "PlanRowStatus",
    "SafetyRow",
    "ScanPlanContext",
    "TargetRow",
    "build_plan_panel",
]


#: Coarse pill-status used by row builders that translate domain results
#: into one of four glyphs.
PlanRowStatus = Literal["ok", "warn", "fail", "info"]


# ---------------------------------------------------------------------------
# Per-section dataclasses — frozen, immutable, no behaviour.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetRow:
    """The TARGET section's data.

    Attributes:
        url: The target URL or empty if the scan is targeting a system
            prompt / framework object (in which case ``mode`` describes
            the actual surface).
        mode: One of ``endpoint`` / ``system_prompt`` / ``framework`` /
            ``code`` / ``contract``.
        reachable: ``True`` iff the reachability preflight came back
            cleanly. ``None`` when no preflight was performed
            (``--no-preflight``, contract mode, non-HTTP surface).
        reachable_latency_ms: First-attempt latency in ms when
            ``reachable`` is ``True``. ``None`` otherwise.
        multi_agent: ``True`` iff the target was declared (or sniffed)
            as a multi-agent orchestrator.
    """

    url: str
    mode: str
    reachable: bool | None
    reachable_latency_ms: int | None
    multi_agent: bool


@dataclass(frozen=True)
class ModelRow:
    """One row of the MODELS section.

    Attributes:
        role: Which LLM role this row reports on
            (``attacker`` / ``evaluator`` / ``commander``).
        spec: The full ``provider:model`` spec (e.g.
            ``gemini:gemini-2.5-flash``).
        result: Validation outcome from
            :mod:`agent_guardian.llm.validation`.
    """

    role: Literal["attacker", "evaluator", "commander"]
    spec: str
    result: ModelValidationResult


@dataclass(frozen=True)
class BudgetRow:
    """The BUDGET section's data.

    Attributes:
        mode: One of ``fast`` / ``smart`` / ``full``.
        mode_threshold_pct: The minimum-coverage % required for the
            chosen mode to keep ``scoring_valid=True``. Sourced from
            :data:`agent_guardian.reports.warnings.MODE_AUTHORITATIVE_THRESHOLDS`.
        wall_seconds_cap: Wall-clock cap in seconds, or ``None`` for
            uncapped.
        usd_cap: USD cap, or ``None`` for uncapped.
        estimated_cost_lo: Low end of the per-mode estimated cost (USD).
        estimated_cost_hi: High end of the per-mode estimated cost (USD).
    """

    mode: str
    mode_threshold_pct: float
    wall_seconds_cap: int | None
    usd_cap: float | None
    estimated_cost_lo: float
    estimated_cost_hi: float


@dataclass(frozen=True)
class OutputRow:
    """One row of the OUTPUTS section.

    Attributes:
        format: The ``--output`` format string (lower-case).
        engine_check: The result from
            :func:`agent_guardian.reports.output_engines.validate_output_engine_available`.
        output_path: Resolved ``--output-path`` (or empty if the scan
            will write to the default location).
    """

    format: str
    engine_check: EngineCheck
    output_path: str


@dataclass(frozen=True)
class DashboardRow:
    """The DASHBOARD section's data.

    Attributes:
        url: The dashboard URL that will be emitted in the scan output
            (e.g. ``http://127.0.0.1:7474/scans/cli-abc123``).
        spawned: ``True`` iff the auto-serve manager spawned a child
            process for this scan.
        reused: ``True`` iff an existing AG serve was detected and the
            scan is reusing it.
        suppression_reason: Reason auto-serve was suppressed (one of
            the locked QA-009 reason strings) or ``None`` when active.
    """

    url: str
    spawned: bool
    reused: bool
    suppression_reason: str | None


@dataclass(frozen=True)
class SafetyRow:
    """The SAFETY GUARDS section's data.

    Attributes:
        contract_path: Path to the contract file, or empty when not in
            ``--contract`` mode.
        roe_blocklist: Tools the contract forbids the swarm from
            touching. Empty tuple when no contract / no blocklist.
        roe_allowlist: Tools the contract restricts the swarm to.
            Empty tuple when no contract / no allowlist.
        authorization_ref: The contract's ``roe.authorization_ref`` (or
            ``"n/a"`` when not in contract mode).
        egress_label: Human-readable summary of the egress policy
            (``"unrestricted"`` / ``"allowlisted"`` / ``"blocked"``).
    """

    contract_path: str
    roe_blocklist: tuple[str, ...]
    roe_allowlist: tuple[str, ...]
    authorization_ref: str
    egress_label: str


@dataclass(frozen=True)
class ScanPlanContext:
    """The fully-validated state the plan panel renders from.

    The CLI assembles this via
    :func:`agent_guardian.ui.scan_plan_data.build_plan_context` after
    every probe has run. The renderer does NOT re-run any of them.

    Attributes:
        scan_id: The scan ID (``cli-<hex>``).
        target: :class:`TargetRow` for the TARGET section.
        models: One :class:`ModelRow` per distinct attacker / evaluator
            / commander spec.
        budget: :class:`BudgetRow` for the BUDGET section.
        outputs: One :class:`OutputRow` per requested format. Today the
            CLI always passes a single format; the tuple shape is
            future-proof for ``--output a,b,c`` style multi-format
            emission.
        dashboard: :class:`DashboardRow` for the DASHBOARD section.
        safety: :class:`SafetyRow` for the SAFETY GUARDS section.
        warnings: Aggregated WARNINGS lines (one per ✗ row), in
            display order. Empty tuple → WARNINGS section is omitted.
    """

    scan_id: str
    target: TargetRow
    models: tuple[ModelRow, ...]
    budget: BudgetRow
    outputs: tuple[OutputRow, ...]
    dashboard: DashboardRow
    safety: SafetyRow
    warnings: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Pill glyphs — sourced from one place so a future restyle is mechanical.
# ---------------------------------------------------------------------------


_PILL_OK = "[green]✓[/]"
_PILL_FAIL = "[red]✗[/]"
_PILL_WARN = "[yellow]⚠[/]"
_PILL_INFO = "[cyan]·[/]"


def _escape(text: str) -> str:
    """Escape Rich markup metacharacters in operator-supplied strings.

    The plan panel embeds free-text strings sourced from probe results
    (install hints, error messages, etc.). Those may contain ``[`` /
    ``]`` characters — most famously ``pip install foo[extra]`` —
    which Rich would otherwise parse as start-of-tag and silently
    elide. We escape every interpolated field so the output is
    literal.
    """
    return _rich_escape(text)


def _pill(status: PlanRowStatus) -> str:
    """Return a Rich-markup glyph for a row pill."""
    if status == "ok":
        return _PILL_OK
    if status == "fail":
        return _PILL_FAIL
    if status == "warn":
        return _PILL_WARN
    return _PILL_INFO


# ---------------------------------------------------------------------------
# Per-row status mappers — each translates domain state → PlanRowStatus.
# ---------------------------------------------------------------------------


def _target_reachable_status(target: TargetRow) -> PlanRowStatus:
    """Map ``TargetRow.reachable`` to a pill status."""
    if target.reachable is None:
        # No preflight performed — neutral, not failure.
        return "info"
    return "ok" if target.reachable else "fail"


def _model_status(result: ModelValidationResult) -> PlanRowStatus:
    """Map a model-validation result to a pill status."""
    if result.status == "valid":
        return "ok"
    if result.status in ("not_found", "auth_failed"):
        return "fail"
    # transient / unsupported / anything else — surface as warn so the
    # operator sees the row but the scan can continue.
    return "warn"


def _output_status(check: EngineCheck) -> PlanRowStatus:
    """Map an :class:`EngineCheck` to a pill status."""
    if check.status == "ok":
        return "ok"
    if check.status == "missing":
        return "fail"
    # unknown_format
    return "fail"


def _dashboard_status(row: DashboardRow) -> PlanRowStatus:
    """Map a :class:`DashboardRow` to a pill status."""
    if row.spawned or row.reused:
        return "ok"
    # suppressed — operator opted out via flag / env / non-TTY.
    return "warn"


# ---------------------------------------------------------------------------
# Section builders. Each returns a ``rich.table.Table`` grid.
# ---------------------------------------------------------------------------


def _grid(title: str) -> Table:
    """Return a borderless 2-column grid with a section header row."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", width=20, no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row(Text(title, style="bold cyan"), "")
    return grid


def _section_target(target: TargetRow) -> Table:
    grid = _grid("TARGET")
    if target.url:
        grid.add_row("  URL", target.url)
    grid.add_row("  Mode", target.mode)
    reachable_pill = _pill(_target_reachable_status(target))
    if target.reachable is None:
        reachable_text = f"{reachable_pill} not preflighted (offline / contract / non-HTTP)"
    elif target.reachable:
        latency = (
            f"{target.reachable_latency_ms} ms" if target.reachable_latency_ms is not None else "ok"
        )
        reachable_text = f"{reachable_pill} reachable in {latency}"
    else:
        reachable_text = f"{reachable_pill} unreachable"
    grid.add_row("  Reachable", reachable_text)
    multi_agent_text = (
        "yes (orchestrator declared)" if target.multi_agent else "no (single endpoint)"
    )
    grid.add_row("  Multi-agent", multi_agent_text)
    return grid


def _section_models(models: tuple[ModelRow, ...]) -> Table:
    grid = _grid("MODELS")
    if not models:
        grid.add_row("  (none)", "")
        return grid
    for row in models:
        pill = _pill(_model_status(row.result))
        if row.result.status == "valid":
            tail = "validated"
        elif row.result.status == "transient":
            tail = "transient (will surface at first call)"
        elif row.result.status == "auth_failed":
            tail = "auth failed"
        elif row.result.status == "not_found":
            tail = "not found"
        else:
            tail = row.result.status
        grid.add_row(f"  {row.role.capitalize()}", f"{row.spec}   {pill} {tail}")
    return grid


def _section_budget(budget: BudgetRow) -> Table:
    grid = _grid("BUDGET")
    grid.add_row(
        "  Mode",
        f"{budget.mode} ({int(budget.mode_threshold_pct)}% coverage threshold)",
    )
    if budget.wall_seconds_cap is not None:
        minutes = budget.wall_seconds_cap // 60
        seconds = budget.wall_seconds_cap % 60
        if minutes and seconds:
            wall = f"{minutes} min {seconds} s"
        elif minutes:
            wall = f"{minutes} min"
        else:
            wall = f"{seconds} s"
        grid.add_row("  Wall-clock cap", wall)
    else:
        grid.add_row("  Wall-clock cap", "uncapped")
    if budget.usd_cap is not None:
        grid.add_row("  USD cap", f"${budget.usd_cap:.4f}")
    else:
        grid.add_row("  USD cap", "uncapped")
    grid.add_row(
        "  Estimated cost",
        f"${budget.estimated_cost_lo:.4f} - ${budget.estimated_cost_hi:.4f} "
        f"(typical for {budget.mode} mode)",
    )
    return grid


def _section_outputs(outputs: tuple[OutputRow, ...]) -> Table:
    grid = _grid("OUTPUTS")
    if not outputs:
        grid.add_row("  (none)", "")
        return grid
    for row in outputs:
        pill = _pill(_output_status(row.engine_check))
        check = row.engine_check
        if check.status == "ok":
            tail = f"{check.engine}"
        elif check.status == "missing":
            tail = f"NOT AVAILABLE — {_escape(check.install_hint)}"
        else:  # unknown_format
            tail = _escape(check.message or "unknown format")
        grid.add_row(f"  --output {row.format}", f"{pill} {tail}")
        if row.output_path:
            grid.add_row("  --output-path", row.output_path)
    return grid


def _section_dashboard(dashboard: DashboardRow) -> Table:
    grid = _grid("DASHBOARD")
    grid.add_row("  URL", dashboard.url)
    pill = _pill(_dashboard_status(dashboard))
    if dashboard.spawned:
        status_text = f"{pill} auto-served (child spawned)"
    elif dashboard.reused:
        status_text = f"{pill} reusing existing serve"
    else:
        reason = dashboard.suppression_reason or "suppressed"
        status_text = f"{pill} {reason}"
    grid.add_row("  Server status", status_text)
    return grid


def _section_safety(safety: SafetyRow) -> Table:
    grid = _grid("SAFETY GUARDS")
    if safety.contract_path:
        grid.add_row("  Contract", safety.contract_path)
    if safety.roe_blocklist:
        grid.add_row("  RoE blocklist", ", ".join(safety.roe_blocklist))
    else:
        grid.add_row("  RoE blocklist", "none")
    if safety.roe_allowlist:
        grid.add_row("  RoE allowlist", ", ".join(safety.roe_allowlist))
    grid.add_row("  Authorization", safety.authorization_ref or "n/a")
    grid.add_row("  Egress policy", safety.egress_label)
    return grid


def _section_warnings(warnings: tuple[str, ...]) -> Table:
    grid = _grid("WARNINGS")
    for warning in warnings:
        grid.add_row("", f"{_PILL_WARN} {_escape(warning)}")
    return grid


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------


def build_plan_panel(ctx: ScanPlanContext) -> Panel:
    """Return the Rich Panel for the scan-plan (Phase 0) board.

    Pure: no I/O. Same ctx in → equivalent Panel out. The function
    never re-runs probes; it only composes the seven section grids
    and wraps them in a Panel.

    Args:
        ctx: Fully-validated :class:`ScanPlanContext` assembled by the
            CLI from upstream probe results.

    Returns:
        A :class:`rich.panel.Panel` with title
        ``"Scan plan · <scan_id>"`` and the seven section grids
        (WARNINGS omitted when empty).
    """
    sections: list[Table] = [
        _section_target(ctx.target),
        _section_models(ctx.models),
        _section_budget(ctx.budget),
        _section_outputs(ctx.outputs),
        _section_dashboard(ctx.dashboard),
        _section_safety(ctx.safety),
    ]
    if ctx.warnings:
        sections.append(_section_warnings(ctx.warnings))
    body = Group(*sections)
    return Panel(
        body,
        title=f"Scan plan · {ctx.scan_id}",
        title_align="left",
        box=box.ROUNDED,
        padding=(1, 2),
    )
