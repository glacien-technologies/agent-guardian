"""Unit tests for the v1.1 three-mode scan system (FAST / SMART / FULL).

Covers:

1. ``SwarmConfig.__post_init__`` correctly applies each mode's preset
   to the un-overridden knobs.
2. ``SwarmCommander._checkpoint`` honours the
   ``min_turns_before_early_stop`` gate so FULL mode never returns
   EARLY_STOP even with the early-stop *signal* (low variance + no
   recent findings) present.
3. The ``--mode`` CLI flag round-trips through to ``SwarmConfig.mode``.
4. ``Scan`` model carries ``mode`` in the JSON report.
5. ``ScanCompletedEvent`` carries ``mode`` in the ESSENTIAL tier
   (the field exists and accepts every ScanMode value without the
   extended-tier toggle).

These tests are deliberately fast — none of them spin up a real swarm
run. The mode wiring is structural so structural tests are the right
shape.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.cli import app
from agent_guardian.core.swarm import (
    CheckpointDecision,
    ScanMode,
    SwarmCommander,
    SwarmConfig,
)
from agent_guardian.llm.stub import StubLLM, StubScript
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.telemetry.events import ScanCompletedEvent

# ---------------------------------------------------------------------------
# Mode preset wiring
# ---------------------------------------------------------------------------


def test_mode_default_is_full() -> None:
    """Spec: scans without an explicit mode get FULL — most thorough.

    This is the v1.1 BREAKING DEFAULT CHANGE. If this test starts
    failing because someone flipped the default back to SMART for
    "perf reasons," push back: the explicit user request was that
    security tools should be thorough by default.
    """
    config = SwarmConfig(scan_id="t1")
    assert config.mode is ScanMode.FULL


def test_mode_preset_fast_caps_turns_and_probes() -> None:
    """FAST = top-3 probes per agent, 4-turn cap, gate=0 (early-stop enabled)."""
    config = SwarmConfig(scan_id="t1", mode=ScanMode.FAST)
    assert config.mode is ScanMode.FAST
    assert config.probes_per_category == 3
    assert config.max_turns_per_agent == 4
    assert config.min_turns_before_early_stop == 0
    # FAST should *also* relax the variance threshold (more willing to
    # stop early on noisy AIVSS) -- but only if the caller didn't
    # explicitly set the threshold themselves.
    assert config.early_stop_variance_threshold == 5.0


def test_mode_preset_smart_matches_v1_0_behaviour() -> None:
    """SMART = pre-v1.1 default. No probe cap, default turns, gate=0."""
    config = SwarmConfig(scan_id="t1", mode=ScanMode.SMART)
    assert config.mode is ScanMode.SMART
    assert config.probes_per_category is None
    assert config.max_turns_per_agent is None
    assert config.min_turns_before_early_stop == 0
    assert config.early_stop_variance_threshold == 2.0


def test_mode_preset_full_arms_early_stop_gate() -> None:
    """FULL sets gate=999 (>> max_turns=12) so the gate never opens."""
    config = SwarmConfig(scan_id="t1", mode=ScanMode.FULL)
    assert config.mode is ScanMode.FULL
    assert config.min_turns_before_early_stop == 999
    # FULL also pins variance threshold to 0.0 so the EARLY_STOP
    # variance arm itself cannot fire (variance is always >= 0).
    assert config.early_stop_variance_threshold == 0.0


def test_explicit_override_wins_over_preset() -> None:
    """Mode is composable: a test can pick FULL but cap turns at 4.

    This matters because the test suite often wants FULL semantics
    (no early-stop) without paying for a real FULL scan's runtime.
    """
    config = SwarmConfig(scan_id="t1", mode=ScanMode.FULL, max_turns_per_agent=4)
    assert config.mode is ScanMode.FULL
    assert config.max_turns_per_agent == 4  # explicit override survives
    # min_turns_gate still gets FULL's value because the caller didn't
    # override that one.
    assert config.min_turns_before_early_stop == 999


# ---------------------------------------------------------------------------
# _checkpoint() gate behaviour
# ---------------------------------------------------------------------------


def _make_commander(mode: ScanMode) -> SwarmCommander:
    """Construct a SwarmCommander with stubs sufficient for _checkpoint()."""
    config = SwarmConfig(scan_id="t1", mode=mode)
    target = PromptAdapter(
        "test target",
        llm=StubScript().default("ok").build(),
        model="stub",
    )
    return SwarmCommander(
        config=config,
        target=target,
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
        commander_llm=StubLLM(default="ok"),
    )


def _prime_early_stop_signal(commander: SwarmCommander) -> None:
    """Force the conditions under which v1.0 would have returned EARLY_STOP.

    Three samples in the AIVSS window with low variance + the
    no-recent-findings clock pushed past the checkpoint interval.

    NOTE: ``_checkpoint`` appends ``_compute_provisional_aivss()`` to
    the window *before* evaluating variance. With no findings in
    memory that produces 100 (vacuous-max). We pre-seed the window
    with the same value so the resulting window is uniform and
    variance is zero.
    """
    commander._aivss_window = [100, 100, 100]
    commander._last_finding_count = 0
    # Push the last-finding timestamp comfortably into the past so the
    # no-recent-findings half of the signal fires no matter the
    # checkpoint_interval_seconds preset.
    commander._last_finding_seen_at = time.monotonic() - 10_000.0


def test_smart_mode_returns_early_stop_on_signal() -> None:
    """SMART: with the early-stop signal armed, _checkpoint returns EARLY_STOP.

    This is the v1.0 baseline. If this test breaks, the gate's been
    over-tightened and SMART has accidentally become FULL.
    """
    commander = _make_commander(ScanMode.SMART)
    _prime_early_stop_signal(commander)
    assert commander._checkpoint() is CheckpointDecision.EARLY_STOP


def test_full_mode_suppresses_early_stop_even_on_signal() -> None:
    """FULL: same primed signal, the gate must hold and return CONTINUE.

    This is the canary for the entire feature — if FULL ever lets
    EARLY_STOP through, every coverage measurement is suspect.
    """
    commander = _make_commander(ScanMode.FULL)
    _prime_early_stop_signal(commander)
    # FULL pins variance_threshold to 0.0, so the variance arm of the
    # signal can't fire either -- belt-and-braces. Either arm being
    # closed is sufficient; we test both are closed for FULL.
    assert commander._checkpoint() is CheckpointDecision.CONTINUE


def test_fast_mode_allows_early_stop() -> None:
    """FAST: gate is 0 (open) so EARLY_STOP can still fire."""
    commander = _make_commander(ScanMode.FAST)
    _prime_early_stop_signal(commander)
    # FAST raises variance threshold to 5.0, so a zero-variance window
    # passes the variance arm trivially -> EARLY_STOP returns.
    assert commander._checkpoint() is CheckpointDecision.EARLY_STOP


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_mode_flag_appears_in_help() -> None:
    """The --mode option is registered on the scan command, documenting fast/smart/full.

    Introspects the Typer command params rather than the rendered --help text:
    Rich truncates option names at CI's non-tty width and honouring COLUMNS in
    the invoke env is version-dependent, so asserting on rendered text is flaky.
    """
    from click import Group
    from typer.main import get_command

    cmd = get_command(app)
    assert isinstance(cmd, Group)
    scan = cmd.commands["scan"]
    mode_param = next((p for p in scan.params if "--mode" in p.opts), None)
    assert mode_param is not None
    help_text = str(getattr(mode_param, "help", "") or "").lower()
    for token in ("fast", "smart", "full"):
        assert token in help_text


def test_cli_mode_flag_rejects_unknown_value() -> None:
    """Unknown mode = EXIT_CONFIG, not a tracebacks-out-the-bottom crash."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "stub:run", "--mode", "ludicrous", "--model", "stub"])
    # Either typer rejects it (exit 2) or our handler rejects it
    # (EXIT_CONFIG=4). Both are valid; both produce a clear error
    # message instead of crashing the scan.
    assert result.exit_code != 0
    assert "ludicrous" in result.output.lower() or "mode" in result.output.lower()


# ---------------------------------------------------------------------------
# Persistence: Scan JSON + ScanCompletedEvent
# ---------------------------------------------------------------------------


def _make_scan(mode: str) -> Scan:
    return Scan(
        id="scan-test",
        package_version="1.1.0",
        aivss_formula_version="1.0.0",
        probe_library_version="1.0.0",
        target_mode="prompt",
        target_ref="test://target",
        tier=Tier.T3_STANDARD,
        aivss=75,
        band=SeverityBand.GOOD,
        sub_scores={},
        findings=[],
        asi_scores={c: 100.0 for c in AsiCategory},
        duration_seconds=42.0,
        cost_usd=0.01,
        tokens_total=1000,
        mode=mode,  # type: ignore[arg-type]
        created_at=datetime.now(timezone.utc),
    )


@pytest.mark.parametrize("mode", ["fast", "smart", "full"])
def test_scan_model_round_trips_mode(mode: str) -> None:
    """Mode must round-trip through model_dump / model_validate."""
    scan = _make_scan(mode)
    serialised = scan.model_dump()
    assert serialised["mode"] == mode
    deserialised = Scan.model_validate(serialised)
    assert deserialised.mode == mode


def test_scan_model_defaults_to_smart_for_legacy_json() -> None:
    """Old Scan JSON files (no `mode` key) must still deserialise.

    The default is "smart" -- it most accurately reflects the
    behaviour the v1.0 swarm actually had (early-stop enabled,
    full corpus). This keeps the analytics dashboard honest when
    re-loading historical scans.
    """
    payload = _make_scan("smart").model_dump()
    payload.pop("mode")  # simulate v1.0 JSON
    deserialised = Scan.model_validate(payload)
    assert deserialised.mode == "smart"


@pytest.mark.parametrize("mode", ["fast", "smart", "full"])
def test_telemetry_event_carries_mode(mode: str) -> None:
    """ScanCompletedEvent must accept and preserve every ScanMode value.

    Mode is ESSENTIAL-tier metadata (operational, non-identifying) so
    it must be settable without any extended-tier toggle.
    """
    now = datetime.now(timezone.utc)
    event = ScanCompletedEvent(
        install_id="12345678-1234-1234-1234-123456789abc",
        scan_id="scan-test",
        aivss=75,
        band="GOOD",
        tier="T3",
        mode=mode,  # type: ignore[arg-type]
        duration_seconds=42.0,
        terminated_by="success",
        agents_count=11,
        attempts_count=33,
        successes_count=22,
        findings_total=2,
        findings_critical=0,
        findings_high=1,
        findings_medium=1,
        findings_low=0,
        agent_version="1.1.0",
        started_at=now,
        completed_at=now,
    )
    assert event.mode == mode
    # Round-trip through JSON to mirror what the collector will see.
    on_wire = event.model_dump(mode="json")
    assert on_wire["mode"] == mode


def test_telemetry_event_defaults_mode_to_smart() -> None:
    """An old client (no mode in payload) must still deserialise.

    The collector accepts an event without `mode` and treats it as
    SMART -- matching the v1.0 behaviour. Same rationale as the
    Scan model: do not silently shift historical aggregates by
    re-bucketing legacy data as FULL.
    """
    now = datetime.now(timezone.utc)
    base = {
        "install_id": "12345678-1234-1234-1234-123456789abc",
        "scan_id": "scan-test",
        "aivss": 75,
        "band": "GOOD",
        "tier": "T3",
        "duration_seconds": 42.0,
        "terminated_by": "success",
        "agents_count": 11,
        "attempts_count": 33,
        "successes_count": 22,
        "findings_total": 0,
        "findings_critical": 0,
        "findings_high": 0,
        "findings_medium": 0,
        "findings_low": 0,
        "agent_version": "1.0.0",
        "started_at": now.isoformat(),
        "completed_at": now.isoformat(),
    }
    event = ScanCompletedEvent.model_validate(base)
    assert event.mode == "smart"


# ---------------------------------------------------------------------------
# Imports unused above (kept to surface API drift): if these symbols get
# renamed, the module fails to import and the whole test file errors,
# which is the early-warning system we want.
# ---------------------------------------------------------------------------
_ = (Finding, Severity)
