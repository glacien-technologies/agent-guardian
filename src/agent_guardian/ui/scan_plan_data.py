"""Assemble :class:`ScanPlanContext` from validated CLI state (QA-011).

The CLI keeps the side-effecting probes — model validation in
``cli.py`` 6a (QA-001), output-engine validation in 6a-bis (QA-010),
endpoint preflight (hoisted to before the panel), auto-serve probe
(QA-009). This module only wires those results into the dataclasses
:mod:`agent_guardian.ui.scan_plan` consumes — no I/O of its own.

Locked decisions (DESIGN_LOCK §3 L14 — DRY engine validator):

* ``model_results`` is retained from ``cli.py`` 6a as a list of
  ``(role, spec, ModelValidationResult)``; this module does NOT re-probe.
* ``engine_checks`` is retained from ``cli.py`` 6a-bis; this module does
  NOT re-probe.
* ``warnings`` is aggregated mechanically from any row that resolved to a
  ✗ or ⚠ pill — never hand-typed at the call site.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final, Literal

from agent_guardian.llm.validation import ModelValidationResult
from agent_guardian.reports.output_engines import EngineCheck
from agent_guardian.reports.warnings import MODE_AUTHORITATIVE_THRESHOLDS
from agent_guardian.ui.auto_serve import AutoServeResult
from agent_guardian.ui.scan_plan import (
    BudgetRow,
    DashboardRow,
    ModelRow,
    OutputRow,
    SafetyRow,
    ScanPlanContext,
    TargetRow,
)

__all__ = [
    "DEFAULT_SAFETY_ROW",
    "MODE_COST_USD",
    "build_plan_context",
    "default_safety_row",
]


#: Locked per-mode estimated-cost table. Values approximate (sourced from
#: historical scan-stats CSVs in QA-011 ticket L206) and surface in the
#: BUDGET row's "Estimated cost" line. Re-tuned per release.
MODE_COST_USD: Final[dict[str, tuple[float, float]]] = {
    "fast": (0.005, 0.010),
    "smart": (0.020, 0.040),
    "full": (0.040, 0.080),
}


#: Default SAFETY GUARDS row used when no ``--contract`` is supplied. The
#: ``--endpoint`` / ``--system-prompt`` / ``--framework`` modes don't
#: carry an RoE document, so the row summarises the unrestricted defaults.
DEFAULT_SAFETY_ROW: Final[SafetyRow] = SafetyRow(
    contract_path="",
    roe_blocklist=(),
    roe_allowlist=(),
    authorization_ref="n/a",
    egress_label="unrestricted",
)


def default_safety_row(*, target_url: str | None = None) -> SafetyRow:
    """Return the default :class:`SafetyRow` for a non-contract scan.

    Kept as a function (not just the module constant) so future modes
    can branch on ``target_url`` shape without a downstream API change.
    """
    _ = target_url  # reserved for future per-mode tweaks
    return DEFAULT_SAFETY_ROW


def _resolve_mode_threshold(mode: str) -> float:
    """Map a ``--mode`` string to its authoritativeness threshold %."""
    key = mode.lower().strip()
    if key in MODE_AUTHORITATIVE_THRESHOLDS:
        return MODE_AUTHORITATIVE_THRESHOLDS[key]  # type: ignore[index]
    return 0.0


def _resolve_mode_cost(mode: str) -> tuple[float, float]:
    """Map a ``--mode`` string to its (low, high) USD estimate."""
    return MODE_COST_USD.get(mode.lower().strip(), (0.0, 0.0))


def _build_target_row(
    *,
    target_url: str | None,
    target_mode: str,
    reachable: bool | None,
    reachable_latency_ms: int | None,
    multi_agent: bool,
) -> TargetRow:
    return TargetRow(
        url=target_url or "",
        mode=target_mode,
        reachable=reachable,
        reachable_latency_ms=reachable_latency_ms,
        multi_agent=multi_agent,
    )


def _build_model_rows(
    model_results: Iterable[tuple[str, str, ModelValidationResult]],
) -> tuple[ModelRow, ...]:
    """Convert raw model-results into :class:`ModelRow` tuples."""
    rows: list[ModelRow] = []
    for role, spec, result in model_results:
        role_lit: Literal["attacker", "evaluator", "commander"]
        if role == "attacker":
            role_lit = "attacker"
        elif role == "evaluator":
            role_lit = "evaluator"
        elif role == "commander":
            role_lit = "commander"
        else:
            # Defensive — the CLI only ever passes the three locked roles.
            continue
        rows.append(ModelRow(role=role_lit, spec=spec, result=result))
    return tuple(rows)


def _build_budget_row(
    *,
    mode: str,
    wall_seconds_cap: int | None,
    usd_cap: float | None,
) -> BudgetRow:
    threshold = _resolve_mode_threshold(mode)
    lo, hi = _resolve_mode_cost(mode)
    return BudgetRow(
        mode=mode,
        mode_threshold_pct=threshold,
        wall_seconds_cap=wall_seconds_cap,
        usd_cap=usd_cap,
        estimated_cost_lo=lo,
        estimated_cost_hi=hi,
    )


def _build_output_rows(
    requested_outputs: Iterable[tuple[str, EngineCheck, str]],
) -> tuple[OutputRow, ...]:
    rows: list[OutputRow] = []
    for fmt, check, path in requested_outputs:
        rows.append(OutputRow(format=fmt, engine_check=check, output_path=path))
    return tuple(rows)


def _build_dashboard_row(
    *,
    auto_serve_result: AutoServeResult,
    dashboard_url: str,
) -> DashboardRow:
    return DashboardRow(
        url=dashboard_url,
        spawned=auto_serve_result.spawned,
        reused=auto_serve_result.reused,
        suppression_reason=auto_serve_result.suppression_reason,
    )


def _aggregate_warnings(
    *,
    target: TargetRow,
    models: tuple[ModelRow, ...],
    outputs: tuple[OutputRow, ...],
    dashboard: DashboardRow,
) -> tuple[str, ...]:
    """Mechanically collect one warning line per ✗ / ⚠ row.

    The aggregator never invents text; every line traces back to a
    concrete field on one of the row dataclasses. This is the single
    source for the WARNINGS section so the panel and the post-panel
    summary stay in lockstep.
    """
    out: list[str] = []
    if target.reachable is False:
        out.append(
            f"Target unreachable — {target.url or 'target'}; scan will burn budget "
            "on per-probe timeouts."
        )
    for row in models:
        result = row.result
        if result.status == "not_found":
            out.append(
                f"Model {row.spec} ({row.role}) not found on provider — "
                "scan will fail at first call."
            )
        elif result.status == "auth_failed":
            out.append(f"Model {row.spec} ({row.role}) auth failed — set the right API key.")
        elif result.status == "transient":
            out.append(
                f"Model {row.spec} ({row.role}) probe was transient — "
                "scan will surface the error at first call."
            )
    for orow in outputs:
        check = orow.engine_check
        if check.status == "missing":
            out.append(
                f"Output engine missing for --output {orow.format} — "
                f"{check.install_hint}; scan will fail at write-time."
            )
        elif check.status == "unknown_format":
            out.append(
                f"Unknown --output {orow.format!r} — see "
                "`agent-guardian scan --help` for supported formats."
            )
    if dashboard.suppression_reason is not None:
        # Non-spawn cases are explicit operator choices most of the time
        # (--no-tui, --no-publish, $CI). Surface as a one-liner so the
        # operator sees the dashboard URL won't auto-resolve.
        out.append(
            "Dashboard auto-serve suppressed "
            f"({dashboard.suppression_reason}) — start `agent-guardian serve` "
            "yourself if you need the URL to work."
        )
    return tuple(out)


def build_plan_context(
    *,
    scan_id: str,
    target_url: str | None,
    target_mode: str,
    reachable: bool | None,
    reachable_latency_ms: int | None,
    multi_agent: bool,
    model_results: Iterable[tuple[str, str, ModelValidationResult]],
    budget_mode: str,
    wall_seconds_cap: int | None,
    usd_cap: float | None,
    requested_outputs: Iterable[tuple[str, EngineCheck, str]],
    auto_serve_result: AutoServeResult,
    dashboard_url: str,
    safety: SafetyRow,
) -> ScanPlanContext:
    """Return a fully-populated :class:`ScanPlanContext`.

    Every probe must have already run; this function aggregates the
    results into the dataclass tree the renderer consumes. Warnings
    are derived mechanically — any ✗ row contributes exactly one line.

    Args:
        scan_id: ``cli-<hex>`` scan identifier.
        target_url: The target URL (or ``None`` for non-HTTP modes).
        target_mode: One of ``endpoint`` / ``system_prompt`` /
            ``framework`` / ``code`` / ``contract``.
        reachable: Outcome of the endpoint preflight (``None`` when
            no preflight was performed).
        reachable_latency_ms: First-attempt latency in ms when
            ``reachable`` is ``True``.
        multi_agent: ``True`` iff the target is a declared / sniffed
            multi-agent orchestrator.
        model_results: One ``(role, spec, ModelValidationResult)``
            tuple per distinct attacker / evaluator / commander spec.
        budget_mode: ``--mode`` value (``fast`` / ``smart`` / ``full``).
        wall_seconds_cap: Wall-clock cap (seconds) or ``None``.
        usd_cap: USD cap or ``None``.
        requested_outputs: One ``(format, EngineCheck, output_path)``
            tuple per requested ``--output`` format.
        auto_serve_result: Outcome of the QA-009 auto-serve manager's
            ``__enter__`` call.
        dashboard_url: Pre-formatted dashboard URL (typically
            ``http://127.0.0.1:7474/scans/<scan_id>``).
        safety: :class:`SafetyRow` from either the contract or the
            CLI defaults.

    Returns:
        A :class:`ScanPlanContext` ready for
        :func:`agent_guardian.ui.scan_plan.build_plan_panel`.
    """
    target = _build_target_row(
        target_url=target_url,
        target_mode=target_mode,
        reachable=reachable,
        reachable_latency_ms=reachable_latency_ms,
        multi_agent=multi_agent,
    )
    models = _build_model_rows(model_results)
    budget = _build_budget_row(
        mode=budget_mode,
        wall_seconds_cap=wall_seconds_cap,
        usd_cap=usd_cap,
    )
    outputs = _build_output_rows(requested_outputs)
    dashboard = _build_dashboard_row(
        auto_serve_result=auto_serve_result,
        dashboard_url=dashboard_url,
    )
    warnings = _aggregate_warnings(
        target=target,
        models=models,
        outputs=outputs,
        dashboard=dashboard,
    )
    return ScanPlanContext(
        scan_id=scan_id,
        target=target,
        models=models,
        budget=budget,
        outputs=outputs,
        dashboard=dashboard,
        safety=safety,
        warnings=warnings,
    )
