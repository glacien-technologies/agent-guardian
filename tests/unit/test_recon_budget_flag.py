"""--recon-budget-seconds CLI flag — opt-in cap on the recon-phase wall budget.

Three unit-level invariants:
  1. The SwarmConfig default ``recon_wall_seconds`` is None (uncapped) per
     the operator "no arbitrary hardcoded caps" rule. Symmetric with the
     QA-027 removal of the legacy 900s wall-cap. Operators opt in to a cap
     via --recon-budget-seconds N for cold-start targets that benefit from
     a hard ceiling (Cloud Run / Lambda / Knative).
  2. The config accepts an explicit float when opt-in.
  3. ``agent-guardian scan --recon-budget-seconds N`` shows up in the help
     text and accepts a numeric value (typer-side validation; the actual
     wiring into the swarm engine is integration-tested elsewhere).
"""

from __future__ import annotations

from typer.testing import CliRunner

from agent_guardian.cli import app
from agent_guardian.core.swarm import SwarmConfig


def test_swarm_config_default_recon_wall_seconds_is_uncapped() -> None:
    """Default is None (uncapped) — opt-in cap only."""
    cfg = SwarmConfig(scan_id="t")
    assert cfg.recon_wall_seconds is None


def test_swarm_config_accepts_custom_recon_wall_seconds() -> None:
    """Operator override (via --recon-budget-seconds) flows through to the config."""
    cfg = SwarmConfig(scan_id="t", recon_wall_seconds=600.0)
    assert cfg.recon_wall_seconds == 600.0


def test_scan_help_advertises_recon_budget_seconds_flag() -> None:
    """The new flag must be discoverable in --help so operators find the escape hatch."""
    from tests._ansi import normalise_help

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    # Normalise ANSI + soft-wrap so flag-name substring asserts are robust
    # against Rich/Click rendering quirks on CI's narrow-terminal CliRunner.
    # See tests/_ansi.py + conftest._force_wide_terminal_for_click.
    normalised = normalise_help(result.stdout)
    assert "--recon-budget-seconds" in normalised
    # Help blurb mentions "cold-start" so operators hitting the silent-skip
    # surface from cold-start targets can grep for the flag.
    lowered = normalised.lower()
    assert "cold-start" in lowered or "cold start" in lowered
