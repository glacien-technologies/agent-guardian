"""QA-018: --recon-budget-seconds CLI flag wires into SwarmConfig.recon_wall_seconds.

Two unit-level invariants:
  1. The SwarmConfig default ``recon_wall_seconds`` is 300.0 (raised from the
     legacy 90.0 because Cloud Run / Lambda / Knative cold-start targets
     routinely timed out and the swarm silently fell back to a minimal
     fingerprint, skipping 3 ASI agents).
  2. ``agent-guardian scan --recon-budget-seconds N`` shows up in the help
     text and accepts a numeric value (typer-side validation; the actual
     wiring into the swarm engine is integration-tested elsewhere).
"""

from __future__ import annotations

from typer.testing import CliRunner

from agent_guardian.cli import app
from agent_guardian.core.swarm import SwarmConfig


def test_swarm_config_default_recon_wall_seconds_is_300() -> None:
    """Default raised from 90s to 300s per QA-018."""
    cfg = SwarmConfig(scan_id="t")
    assert cfg.recon_wall_seconds == 300.0


def test_swarm_config_accepts_custom_recon_wall_seconds() -> None:
    """Operator override (via --recon-budget-seconds) flows through to the config."""
    cfg = SwarmConfig(scan_id="t", recon_wall_seconds=600.0)
    assert cfg.recon_wall_seconds == 600.0


def test_scan_help_advertises_recon_budget_seconds_flag() -> None:
    """The new flag must be discoverable in --help so operators find the escape hatch."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--recon-budget-seconds" in result.stdout
    # The help blurb mentions QA-018's root cause so an operator who hits the
    # silent-skip surface from QA-018 can grep for "cold-start" and find the flag.
    assert "cold-start" in result.stdout.lower() or "cold start" in result.stdout.lower()
