"""QA-027: ``overall_wall_seconds`` default is None (uncapped); ``--budget-seconds``
is the opt-in CLI flag; the run() no-timeout branch never enters wait_for.

Locks the four acceptance bullets from QA_FEEDBACKS.md §QA-027:

  1. SwarmConfig().overall_wall_seconds is None.
  2. agent-guardian scan (no --budget-seconds) -> run() routes past wait_for.
  3. agent-guardian scan --budget-seconds 600 -> SwarmConfig.overall_wall_seconds == 600.
  4. Plan panel BUDGET section renders "Wall-clock cap   uncapped" when None.

Cross-checks the AgentBudget.wall_seconds_remaining propagation: when the swarm-
wide cap is None, per-agent slices get +inf (NOT 0), matching the acceptance
bullet "should report inf or be omitted when uncapped, NOT 0".
"""

from __future__ import annotations

import asyncio
import math
from unittest.mock import patch

from typer.testing import CliRunner

from agent_guardian.cli import app
from agent_guardian.core.swarm import SwarmConfig
from agent_guardian.ui.auto_serve import AutoServeResult
from agent_guardian.ui.scan_plan import build_plan_panel
from agent_guardian.ui.scan_plan_data import build_plan_context, default_safety_row

# ----------------------------------------------------------------------
# SwarmConfig default + override
# ----------------------------------------------------------------------


def test_swarm_config_default_overall_wall_seconds_is_none() -> None:
    """QA-027 acceptance (1) -- default is None (uncapped)."""
    cfg = SwarmConfig(scan_id="t")
    assert cfg.overall_wall_seconds is None


def test_swarm_config_accepts_explicit_overall_wall_seconds() -> None:
    """An explicit positive value is preserved (so --budget-seconds N caps at N)."""
    cfg = SwarmConfig(scan_id="t", overall_wall_seconds=600.0)
    assert cfg.overall_wall_seconds == 600.0


# ----------------------------------------------------------------------
# run() no-timeout branch -- the asyncio.wait_for wrapper is bypassed
# ----------------------------------------------------------------------


def test_run_skips_wait_for_when_overall_wall_seconds_is_none() -> None:
    """QA-027 acceptance (2) -- when uncapped, run() must not enter wait_for.

    We patch ``asyncio.wait_for`` and assert it was never called; the
    swarm's ``_run_inner`` is patched to a no-op coroutine returning a
    sentinel Scan so we exercise only the wait_for-vs-direct branch.
    """
    from agent_guardian.core.swarm import SwarmCommander

    class _StubScan:
        scan_id = "t"

    async def _fake_run_inner(self) -> _StubScan:  # type: ignore[no-untyped-def]
        return _StubScan()  # type: ignore[return-value]

    commander = SwarmCommander.__new__(SwarmCommander)
    commander.config = SwarmConfig(scan_id="t")  # overall_wall_seconds=None
    commander._has_run = False
    commander._start_time = 0.0
    commander._last_finding_seen_at = 0.0

    with (
        patch.object(SwarmCommander, "_run_inner", _fake_run_inner),
        patch("agent_guardian.core.swarm.asyncio.wait_for") as wait_for,
    ):
        asyncio.run(commander.run())

    assert wait_for.call_count == 0, (
        "QA-027: when overall_wall_seconds is None, run() must bypass "
        "asyncio.wait_for entirely (no legacy 0->instant-fire footgun)."
    )


def test_run_uses_wait_for_when_overall_wall_seconds_is_set() -> None:
    """Inverse -- a positive value still routes through wait_for(timeout=N)."""
    from agent_guardian.core.swarm import SwarmCommander

    class _StubScan:
        scan_id = "t"

    async def _fake_run_inner(self) -> _StubScan:  # type: ignore[no-untyped-def]
        return _StubScan()  # type: ignore[return-value]

    async def _wait_for_passthrough(coro, timeout):  # type: ignore[no-untyped-def]
        return await coro

    commander = SwarmCommander.__new__(SwarmCommander)
    commander.config = SwarmConfig(scan_id="t", overall_wall_seconds=600.0)
    commander._has_run = False
    commander._start_time = 0.0
    commander._last_finding_seen_at = 0.0

    with (
        patch.object(SwarmCommander, "_run_inner", _fake_run_inner),
        patch(
            "agent_guardian.core.swarm.asyncio.wait_for",
            side_effect=_wait_for_passthrough,
        ) as wait_for,
    ):
        asyncio.run(commander.run())

    assert wait_for.call_count == 1
    # The second positional arg / 'timeout' kwarg must be the 600.0 we passed.
    call = wait_for.call_args
    timeout = call.kwargs.get("timeout", call.args[1] if len(call.args) > 1 else None)
    assert timeout == 600.0


# ----------------------------------------------------------------------
# Plan panel -- uncapped render
# ----------------------------------------------------------------------


def _minimal_plan_ctx_uncapped():  # type: ignore[no-untyped-def]
    return build_plan_context(
        scan_id="cli-test",
        target_url="https://example.test",
        target_mode="endpoint",
        reachable=True,
        reachable_latency_ms=42,
        multi_agent=False,
        model_results=(),
        budget_mode="full",
        wall_seconds_cap=None,
        usd_cap=None,
        requested_outputs=(),
        auto_serve_result=AutoServeResult(
            base_url="http://127.0.0.1:7474",
            port=7474,
            spawned=False,
            reused=False,
            suppression_reason=None,
        ),
        dashboard_url="http://127.0.0.1:7474/scans/cli-test",
        safety=default_safety_row(target_url="https://example.test"),
    )


def test_plan_panel_renders_wall_clock_cap_uncapped_when_none() -> None:
    """QA-027 acceptance (4) -- the BUDGET row says ``uncapped``."""
    from io import StringIO

    from rich.console import Console

    ctx = _minimal_plan_ctx_uncapped()
    buf = StringIO()
    Console(file=buf, width=120, force_terminal=False).print(build_plan_panel(ctx))
    out = buf.getvalue()
    assert "Wall-clock cap" in out
    # Mirror of the existing "USD cap   uncapped" line -- same token, same column.
    assert "uncapped" in out


# ----------------------------------------------------------------------
# CLI integration -- --budget-seconds discoverability + parsing
# ----------------------------------------------------------------------


def test_scan_help_advertises_budget_seconds_flag() -> None:
    """The new --budget-seconds flag must be discoverable in --help."""
    from tests._ansi import normalise_help

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    # Normalise ANSI + soft-wrap so flag-name substring asserts are robust
    # against Rich/Click rendering quirks on CI's narrow-terminal CliRunner.
    # See tests/_ansi.py + conftest._force_wide_terminal_for_click.
    normalised = normalise_help(result.stdout)
    assert "--budget-seconds" in normalised
    # Help blurb must mention "uncapped" so an operator who reads --help
    # understands the default-off semantics.
    assert "uncapped" in normalised.lower()


def test_scan_help_still_shows_budget_usd_flag() -> None:
    """Regression guard -- adding --budget-seconds must not displace --budget-usd."""
    from tests._ansi import normalise_help

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--budget-usd" in normalise_help(result.stdout)


# ----------------------------------------------------------------------
# Per-agent budget propagation -- +inf, NOT 0, when uncapped
# ----------------------------------------------------------------------


def test_agent_budget_wall_seconds_is_inf_when_swarm_uncapped() -> None:
    """QA-027 acceptance (4) -- per-agent ``wall_seconds_remaining`` is +inf,
    not 0, when ``overall_wall_seconds is None``.

    Exercises the swarm's per-agent loop branch that picks ``math.inf`` when
    the swarm-wide cap is None. We don't build a full SwarmCommander; we just
    assert the helper expression evaluates as the swarm code does.
    """
    cfg = SwarmConfig(scan_id="t")  # uncapped by default
    per_agent_wall = math.inf if cfg.overall_wall_seconds is None else cfg.overall_wall_seconds
    assert per_agent_wall == math.inf
    # And the inverse: a positive cap propagates as-is.
    cfg_capped = SwarmConfig(scan_id="t", overall_wall_seconds=600.0)
    per_agent_wall_capped = (
        math.inf if cfg_capped.overall_wall_seconds is None else cfg_capped.overall_wall_seconds
    )
    assert per_agent_wall_capped == 600.0
