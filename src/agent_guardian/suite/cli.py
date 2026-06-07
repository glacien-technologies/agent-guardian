"""`agent-guardian suite` — YAML-driven multi-workload orchestration CLI.

Additive sub-app; the single-scan ``scan`` command is untouched. Commands:

  suite run SUITE.yaml       launch every workload in parallel + print summary
  suite validate SUITE.yaml  schema + target-mode check, no spawn
  suite summary OUT_DIR      re-print the summary from a prior run's summary.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

from agent_guardian.suite.aggregate import format_summary_lines
from agent_guardian.suite.argv import build_scan_argv
from agent_guardian.suite.errors import SuiteConfigError
from agent_guardian.suite.loader import load_suite_file
from agent_guardian.suite.resolve import resolve_workloads
from agent_guardian.suite.runner import run_suite_sync

_LOG = logging.getLogger(__name__)

suite_app = typer.Typer(
    help="Run a fleet of independent scans in parallel from one YAML suite.",
    no_args_is_help=True,
)

_EXIT_CONFIG = 2


@suite_app.command("run")
def suite_run(
    suite_file: Path = typer.Argument(..., help="Path to the suite YAML."),
    concurrency: int | None = typer.Option(
        None, "--concurrency", help="Max scans in flight (overrides suite.concurrency)."
    ),
    out_dir: Path | None = typer.Option(
        None, "--out-dir", help="Runner workspace (overrides suite.out_dir)."
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the resolved `agent-guardian scan ...` per workload; spawn nothing.",
    ),
) -> None:
    """Launch every workload in parallel as a separate scan, then summarize."""
    try:
        sf = load_suite_file(suite_file)
        resolved = resolve_workloads(sf)
    except SuiteConfigError as exc:
        typer.echo(f"suite config error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_CONFIG) from exc

    if concurrency is not None:
        sf = sf.model_copy(
            update={"suite": sf.suite.model_copy(update={"concurrency": concurrency})}
        )

    if dry_run:
        for wl in resolved:
            argv = " ".join(build_scan_argv(wl))
            home = "isolated HOME" if sf.suite.isolate_home else "shared real HOME"
            typer.echo(f"[{wl.name}] ({home}) agent-guardian {argv}")
        return

    result = run_suite_sync(sf, out_dir=out_dir)
    typer.echo(result.summary_text())

    if sf.suite.serve:
        scans_root = Path.home() / ".agentguardian" / "scans"
        typer.echo(
            f"\nDashboard: registered scans are under {scans_root} — "
            "run `agent-guardian serve` to browse each workload by its scan id."
        )

    raise typer.Exit(code=result.exit_code)


@suite_app.command("validate")
def suite_validate(
    suite_file: Path = typer.Argument(..., help="Path to the suite YAML."),
) -> None:
    """Schema + target-mode check. No scans are launched."""
    try:
        sf = load_suite_file(suite_file)
        resolved = resolve_workloads(sf)
    except SuiteConfigError as exc:
        typer.echo(f"INVALID: {exc}", err=True)
        raise typer.Exit(code=_EXIT_CONFIG) from exc
    typer.echo(
        f"OK: '{sf.suite.name}' — {len(resolved)} workload(s): "
        f"{', '.join(w.name or '?' for w in resolved)}"
    )


@suite_app.command("summary")
def suite_summary(
    out_dir: Path = typer.Argument(..., help="A prior run's out_dir (holds summary.json)."),
) -> None:
    """Re-print the cross-scan summary from a prior run."""
    path = out_dir / "summary.json"
    if not path.is_file():
        typer.echo(f"no summary.json found at {path}", err=True)
        raise typer.Exit(code=_EXIT_CONFIG)
    rows = json.loads(path.read_text(encoding="utf-8")).get("workloads", [])
    typer.echo("\n".join(format_summary_lines(rows)))
