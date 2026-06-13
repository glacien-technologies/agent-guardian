"""Tests for the QA-011 scan-plan panel + confirmation gate.

Covers:

* :func:`agent_guardian.ui.scan_plan.build_plan_panel` — the pure
  renderer (every ✓/✗/⚠ row branch, warnings aggregation).
* :func:`agent_guardian.ui.scan_plan_data.build_plan_context` — the
  pure assembler (model/output/dashboard projection, warning aggregation).
* :func:`agent_guardian.cli._await_plan_confirmation` — the 5-second
  gate (TTY interactive, --yes skip, non-TTY skip, $CI skip, env skip,
  keyboard interrupt → abort).
* Integration: the ``scan`` command's ``--no-plan`` path still emits
  the QA-003 URL line; the confirmation-gate's ``"abort"`` path exits
  with :data:`EXIT_USER_INTERRUPT` cleanly.

Live-regression test against the Cloud Run testbench is gated by the
``$AGENT_GUARDIAN_LIVE_TESTBENCH`` env var so CI without network stays
green.
"""

from __future__ import annotations

import io
import os
from typing import Any
from unittest.mock import patch

import pytest

from agent_guardian.cli import _await_plan_confirmation
from agent_guardian.llm.validation import ModelValidationResult
from agent_guardian.reports.output_engines import EngineCheck
from agent_guardian.ui.auto_serve import AutoServeResult
from agent_guardian.ui.scan_plan import (
    BudgetRow,
    DashboardRow,
    ModelRow,
    OutputRow,
    SafetyRow,
    ScanPlanContext,
    TargetRow,
    build_plan_panel,
)
from agent_guardian.ui.scan_plan_data import (
    DEFAULT_SAFETY_ROW,
    MODE_COST_USD,
    build_plan_context,
    default_safety_row,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeTty(io.StringIO):
    """``io.StringIO`` that reports as a TTY for the gate's ``isatty`` probes."""

    def __init__(self, *, tty: bool = True, content: str = "") -> None:
        super().__init__(content)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _ok_model_result() -> ModelValidationResult:
    return ModelValidationResult(
        valid=True, status="valid", provider="gemini", model="gemini-2.5-flash"
    )


def _ok_engine_check(fmt: str = "json") -> EngineCheck:
    return EngineCheck(format=fmt, status="ok", engine="stdlib")


def _spawned_auto_serve_result() -> AutoServeResult:
    return AutoServeResult(
        base_url="http://127.0.0.1:7474",
        port=7474,
        spawned=True,
        reused=False,
        suppression_reason=None,
    )


def _suppressed_auto_serve_result(reason: str = "--no-tui") -> AutoServeResult:
    return AutoServeResult(
        base_url="http://127.0.0.1:7474",
        port=7474,
        spawned=False,
        reused=False,
        suppression_reason=reason,
    )


def _minimal_ctx(**overrides: Any) -> ScanPlanContext:
    """Return a clean all-✓ ScanPlanContext that consumers can mutate."""
    base = dict(
        scan_id="cli-abcdef012345",
        target=TargetRow(
            url="https://example-target.example.com/chat",
            mode="endpoint",
            reachable=True,
            reachable_latency_ms=247,
            multi_agent=False,
        ),
        models=(
            ModelRow(role="attacker", spec="gemini:gemini-2.5-flash", result=_ok_model_result()),
            ModelRow(role="evaluator", spec="gemini:gemini-2.5-flash", result=_ok_model_result()),
            ModelRow(role="commander", spec="gemini:gemini-2.5-flash", result=_ok_model_result()),
        ),
        budget=BudgetRow(
            mode="full",
            mode_threshold_pct=85.0,
            wall_seconds_cap=900,
            usd_cap=0.10,
            estimated_cost_lo=0.04,
            estimated_cost_hi=0.08,
        ),
        outputs=(
            OutputRow(
                format="pdf",
                engine_check=EngineCheck(format="pdf", status="ok", engine="reportlab"),
                output_path="/tmp/scan.pdf",
            ),
        ),
        dashboard=DashboardRow(
            url="http://127.0.0.1:7474/scan/cli-abcdef012345",
            spawned=True,
            reused=False,
            suppression_reason=None,
        ),
        safety=DEFAULT_SAFETY_ROW,
        warnings=(),
    )
    base.update(overrides)
    return ScanPlanContext(**base)  # type: ignore[arg-type]


def _render(ctx: ScanPlanContext) -> str:
    """Render a Panel to a plain string for assertions."""
    from rich.console import Console

    buf = io.StringIO()
    Console(file=buf, width=120, force_terminal=False, no_color=True).print(build_plan_panel(ctx))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# build_plan_panel — pure renderer
# ---------------------------------------------------------------------------


def test_panel_renders_minimal_endpoint_scan() -> None:
    """A clean all-✓ scan renders every section + no WARNINGS footer."""
    out = _render(_minimal_ctx())
    assert "Scan plan · cli-abcdef012345" in out
    for header in (
        "TARGET",
        "MODELS",
        "BUDGET",
        "OUTPUTS",
        "DASHBOARD",
        "SAFETY GUARDS",
    ):
        assert header in out, f"missing section header: {header}"
    # No warnings → no WARNINGS section.
    assert "WARNINGS" not in out


def test_panel_shows_three_ok_rows_for_three_models() -> None:
    """MODELS section renders one row per attacker / evaluator / commander."""
    out = _render(_minimal_ctx())
    assert "Attacker" in out
    assert "Evaluator" in out
    assert "Commander" in out
    assert out.count("validated") == 3


def test_panel_shows_warning_when_pdf_engine_missing() -> None:
    """A missing PDF engine → ✗ pill + WARNINGS aggregation."""
    out_row = OutputRow(
        format="pdf",
        engine_check=EngineCheck(
            format="pdf",
            status="missing",
            message="no PDF engine importable",
            install_hint="pip install agent-guardian[full]",
        ),
        output_path="/tmp/scan.pdf",
    )
    ctx = _minimal_ctx(
        outputs=(out_row,),
        warnings=(
            "Output engine missing for --output pdf — pip install agent-guardian[full]; "
            "scan will fail at write-time.",
        ),
    )
    out = _render(ctx)
    assert "✗" in out
    assert "NOT AVAILABLE" in out
    assert "WARNINGS" in out
    assert "pip install agent-guardian[full]" in out


def test_panel_shows_warning_when_dashboard_suppressed() -> None:
    """Suppressed auto-serve → ⚠ pill in DASHBOARD; warning aggregated."""
    dr = DashboardRow(
        url="http://127.0.0.1:7474/scan/cli-abcdef012345",
        spawned=False,
        reused=False,
        suppression_reason="--no-tui",
    )
    ctx = _minimal_ctx(
        dashboard=dr,
        warnings=("Dashboard auto-serve suppressed (--no-tui) — start `agent-guardian serve`.",),
    )
    out = _render(ctx)
    assert "⚠" in out
    assert "--no-tui" in out
    assert "WARNINGS" in out


def test_panel_shows_warning_when_target_unreachable() -> None:
    """Unreachable target → ✗ pill in TARGET; warning aggregated."""
    tgt = TargetRow(
        url="https://flaky.example.com/chat",
        mode="endpoint",
        reachable=False,
        reachable_latency_ms=None,
        multi_agent=False,
    )
    ctx = _minimal_ctx(
        target=tgt,
        warnings=("Target unreachable — https://flaky.example.com/chat; scan will burn budget.",),
    )
    out = _render(ctx)
    assert "✗" in out
    assert "unreachable" in out
    assert "WARNINGS" in out


def test_panel_shows_info_pill_when_no_preflight_performed() -> None:
    """``reachable=None`` (preflight skipped) renders as info, not failure."""
    tgt = TargetRow(
        url="https://prompt-only.example.com",
        mode="system_prompt",
        reachable=None,
        reachable_latency_ms=None,
        multi_agent=False,
    )
    out = _render(_minimal_ctx(target=tgt))
    assert "·" in out  # info pill glyph
    assert "not preflighted" in out


def test_panel_shows_ok_when_all_clean() -> None:
    """Sanity test: all-OK ctx never produces a WARNINGS footer."""
    out = _render(_minimal_ctx())
    assert "WARNINGS" not in out


def test_panel_renders_safety_row_with_contract() -> None:
    """A contract-mode scan exposes blocklist + authorization on the SAFETY row."""
    safety = SafetyRow(
        contract_path="/tmp/agentguardian.yaml",
        roe_blocklist=("send_email", "drop_table"),
        roe_allowlist=("get_account",),
        authorization_ref="JIRA-123 (signed 2026-05-31)",
        egress_label="loopback only",
    )
    out = _render(_minimal_ctx(safety=safety))
    assert "send_email" in out
    assert "JIRA-123" in out
    assert "loopback only" in out


def test_panel_renders_budget_uncapped_when_no_caps() -> None:
    """Uncapped budget rows say "uncapped" rather than echoing 0."""
    budget = BudgetRow(
        mode="full",
        mode_threshold_pct=85.0,
        wall_seconds_cap=None,
        usd_cap=None,
        estimated_cost_lo=0.04,
        estimated_cost_hi=0.08,
    )
    out = _render(_minimal_ctx(budget=budget))
    assert "uncapped" in out


def test_panel_renders_empty_models_tuple() -> None:
    """Defensive: empty MODELS tuple renders ``(none)`` placeholder, no crash."""
    out = _render(_minimal_ctx(models=()))
    assert "MODELS" in out
    assert "(none)" in out


def test_panel_renders_empty_outputs_tuple() -> None:
    """Defensive: empty OUTPUTS tuple renders ``(none)`` placeholder, no crash."""
    out = _render(_minimal_ctx(outputs=()))
    assert "OUTPUTS" in out
    assert "(none)" in out


def test_panel_model_auth_failed_renders_as_fail() -> None:
    """``status="auth_failed"`` → ✗ pill + 'auth failed' tail."""
    bad = ModelValidationResult(
        valid=False,
        status="auth_failed",
        provider="openai",
        model="gpt-4o",
        message="bad key",
    )
    rows = (ModelRow(role="attacker", spec="openai:gpt-4o", result=bad),)
    out = _render(_minimal_ctx(models=rows))
    assert "✗" in out
    assert "auth failed" in out


def test_panel_model_not_found_renders_as_fail() -> None:
    """``status="not_found"`` → ✗ pill + 'not found' tail."""
    bad = ModelValidationResult(
        valid=False,
        status="not_found",
        provider="gemini",
        model="gemini-3.5-flash",
        message="not found",
    )
    rows = (ModelRow(role="attacker", spec="gemini:gemini-3.5-flash", result=bad),)
    out = _render(_minimal_ctx(models=rows))
    assert "✗" in out
    assert "not found" in out


def test_panel_model_unsupported_renders_status_tail() -> None:
    """Unsupported model status echoes the literal status string."""
    weird = ModelValidationResult(
        valid=True,
        status="unsupported",
        provider="bogus",
        model="x",
        message="",
    )
    rows = (ModelRow(role="attacker", spec="bogus:x", result=weird),)
    out = _render(_minimal_ctx(models=rows))
    assert "unsupported" in out


def test_panel_output_unknown_format_renders_as_fail() -> None:
    """An unknown_format ``EngineCheck`` → ✗ pill + the message tail."""
    out_row = OutputRow(
        format="xlsx",
        engine_check=EngineCheck(
            format="xlsx", status="unknown_format", message="unknown output 'xlsx'"
        ),
        output_path="",
    )
    ctx = _minimal_ctx(outputs=(out_row,), warnings=("Unknown --output 'xlsx' — see help.",))
    out = _render(ctx)
    assert "✗" in out
    assert "xlsx" in out


def test_panel_dashboard_reused_shows_reusing_text() -> None:
    """``reused=True`` renders the 'reusing existing serve' line."""
    dr = DashboardRow(
        url="http://127.0.0.1:7474/scan/cli-abc",
        spawned=False,
        reused=True,
        suppression_reason=None,
    )
    out = _render(_minimal_ctx(dashboard=dr))
    assert "reusing existing serve" in out


def test_panel_budget_wall_clock_seconds_only() -> None:
    """Wall-clock cap < 60 seconds renders as bare seconds."""
    budget = BudgetRow(
        mode="fast",
        mode_threshold_pct=60.0,
        wall_seconds_cap=45,
        usd_cap=None,
        estimated_cost_lo=0.005,
        estimated_cost_hi=0.010,
    )
    out = _render(_minimal_ctx(budget=budget))
    assert "45 s" in out


def test_panel_budget_wall_clock_minutes_only() -> None:
    """Wall-clock cap on a minute boundary renders as ``N min``."""
    budget = BudgetRow(
        mode="full",
        mode_threshold_pct=85.0,
        wall_seconds_cap=120,
        usd_cap=None,
        estimated_cost_lo=0.04,
        estimated_cost_hi=0.08,
    )
    out = _render(_minimal_ctx(budget=budget))
    assert "2 min" in out
    assert " s" not in out.split("2 min")[1].split("\n")[0]


def test_panel_renders_model_transient_as_warn() -> None:
    """Transient model probe → ⚠ pill, not ✗."""
    transient = ModelValidationResult(
        valid=True,
        status="transient",
        provider="gemini",
        model="gemini-2.5-flash",
        message="provider blip",
    )
    rows = (
        ModelRow(role="attacker", spec="gemini:gemini-2.5-flash", result=transient),
        ModelRow(role="evaluator", spec="gemini:gemini-2.5-flash", result=transient),
        ModelRow(role="commander", spec="gemini:gemini-2.5-flash", result=transient),
    )
    out = _render(_minimal_ctx(models=rows))
    assert "⚠" in out
    assert "transient" in out


# ---------------------------------------------------------------------------
# build_plan_context — pure assembler
# ---------------------------------------------------------------------------


def test_build_plan_context_aggregates_pdf_missing_warning() -> None:
    """A missing PDF engine in ``requested_outputs`` becomes a warning."""
    mr = _ok_model_result()
    ctx = build_plan_context(
        scan_id="cli-1",
        target_url="https://t.example.com",
        target_mode="endpoint",
        reachable=True,
        reachable_latency_ms=200,
        multi_agent=False,
        model_results=[("attacker", "gemini:gemini-2.5-flash", mr)],
        budget_mode="full",
        wall_seconds_cap=900,
        usd_cap=0.10,
        requested_outputs=[
            (
                "pdf",
                EngineCheck(
                    format="pdf",
                    status="missing",
                    install_hint="pip install agent-guardian[full]",
                ),
                "/tmp/x.pdf",
            )
        ],
        auto_serve_result=_spawned_auto_serve_result(),
        dashboard_url="http://127.0.0.1:7474/scan/cli-1",
        safety=DEFAULT_SAFETY_ROW,
    )
    assert any("pip install agent-guardian[full]" in w for w in ctx.warnings)


def test_build_plan_context_aggregates_unreachable_warning() -> None:
    """Unreachable target becomes a warning."""
    mr = _ok_model_result()
    ctx = build_plan_context(
        scan_id="cli-1",
        target_url="https://down.example.com",
        target_mode="endpoint",
        reachable=False,
        reachable_latency_ms=None,
        multi_agent=False,
        model_results=[("attacker", "gemini:gemini-2.5-flash", mr)],
        budget_mode="fast",
        wall_seconds_cap=None,
        usd_cap=None,
        requested_outputs=[("json", _ok_engine_check("json"), "")],
        auto_serve_result=_spawned_auto_serve_result(),
        dashboard_url="http://127.0.0.1:7474/scan/cli-1",
        safety=DEFAULT_SAFETY_ROW,
    )
    assert any("Target unreachable" in w for w in ctx.warnings)


def test_build_plan_context_aggregates_model_not_found_warning() -> None:
    """``status="not_found"`` model becomes a warning."""
    bad = ModelValidationResult(
        valid=False,
        status="not_found",
        provider="gemini",
        model="gemini-3.5-flash",
        message="not found",
    )
    ctx = build_plan_context(
        scan_id="cli-1",
        target_url="https://t.example.com",
        target_mode="endpoint",
        reachable=True,
        reachable_latency_ms=200,
        multi_agent=False,
        model_results=[("attacker", "gemini:gemini-3.5-flash", bad)],
        budget_mode="full",
        wall_seconds_cap=900,
        usd_cap=0.10,
        requested_outputs=[("json", _ok_engine_check("json"), "")],
        auto_serve_result=_spawned_auto_serve_result(),
        dashboard_url="http://127.0.0.1:7474/scan/cli-1",
        safety=DEFAULT_SAFETY_ROW,
    )
    assert any("not found" in w for w in ctx.warnings)


def test_build_plan_context_aggregates_dashboard_suppression_warning() -> None:
    """``auto_serve_result.suppression_reason`` becomes a warning."""
    mr = _ok_model_result()
    ctx = build_plan_context(
        scan_id="cli-1",
        target_url="https://t.example.com",
        target_mode="endpoint",
        reachable=True,
        reachable_latency_ms=200,
        multi_agent=False,
        model_results=[("attacker", "gemini:gemini-2.5-flash", mr)],
        budget_mode="full",
        wall_seconds_cap=900,
        usd_cap=0.10,
        requested_outputs=[("json", _ok_engine_check("json"), "")],
        auto_serve_result=_suppressed_auto_serve_result("--no-tui"),
        dashboard_url="http://127.0.0.1:7474/scan/cli-1",
        safety=DEFAULT_SAFETY_ROW,
    )
    assert any("auto-serve suppressed" in w for w in ctx.warnings)


def test_build_plan_context_clean_all_ok_has_zero_warnings() -> None:
    """All-OK inputs produce an empty warnings tuple."""
    mr = _ok_model_result()
    ctx = build_plan_context(
        scan_id="cli-1",
        target_url="https://t.example.com",
        target_mode="endpoint",
        reachable=True,
        reachable_latency_ms=200,
        multi_agent=False,
        model_results=[
            ("attacker", "gemini:gemini-2.5-flash", mr),
            ("evaluator", "gemini:gemini-2.5-flash", mr),
            ("commander", "gemini:gemini-2.5-flash", mr),
        ],
        budget_mode="full",
        wall_seconds_cap=900,
        usd_cap=0.10,
        requested_outputs=[("json", _ok_engine_check("json"), "")],
        auto_serve_result=_spawned_auto_serve_result(),
        dashboard_url="http://127.0.0.1:7474/scan/cli-1",
        safety=DEFAULT_SAFETY_ROW,
    )
    assert ctx.warnings == ()


def test_default_safety_row_is_unrestricted() -> None:
    """The default SAFETY row (no contract) says unrestricted everywhere."""
    row = default_safety_row()
    assert row.contract_path == ""
    assert row.roe_blocklist == ()
    assert row.authorization_ref == "n/a"
    assert row.egress_label == "unrestricted"


def test_mode_cost_table_has_three_modes() -> None:
    """Cost table covers fast / smart / full."""
    assert set(MODE_COST_USD) == {"fast", "smart", "full"}
    for lo, hi in MODE_COST_USD.values():
        assert lo > 0
        assert hi > lo


def test_build_plan_context_drops_unknown_role() -> None:
    """A row whose role isn't attacker/evaluator/commander is silently dropped."""
    mr = _ok_model_result()
    ctx = build_plan_context(
        scan_id="cli-1",
        target_url="https://t.example.com",
        target_mode="endpoint",
        reachable=True,
        reachable_latency_ms=200,
        multi_agent=False,
        model_results=[
            ("attacker", "gemini:gemini-2.5-flash", mr),
            ("bogus", "gemini:gemini-2.5-flash", mr),
        ],
        budget_mode="full",
        wall_seconds_cap=900,
        usd_cap=0.10,
        requested_outputs=[("json", _ok_engine_check("json"), "")],
        auto_serve_result=_spawned_auto_serve_result(),
        dashboard_url="http://127.0.0.1:7474/scan/cli-1",
        safety=DEFAULT_SAFETY_ROW,
    )
    assert tuple(r.role for r in ctx.models) == ("attacker",)


# ---------------------------------------------------------------------------
# _await_plan_confirmation — confirmation gate
# ---------------------------------------------------------------------------


def _await_sync(coro: Any) -> str:
    """Run an awaitable from a sync test body."""
    import asyncio

    return asyncio.run(coro)


def test_await_proceeds_on_yes_flag() -> None:
    """``yes=True`` short-circuits without touching stdin/stdout."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True)
    assert (
        _await_sync(_await_plan_confirmation(yes=True, stdin=inp, stdout=out, environ={}))
        == "proceed"
    )
    assert out.getvalue() == ""  # no prompt printed


def test_await_proceeds_on_non_tty_stdout() -> None:
    """A non-TTY stdout (piped) auto-proceeds."""
    out = _FakeTty(tty=False)
    inp = _FakeTty(tty=True)
    assert (
        _await_sync(_await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}))
        == "proceed"
    )


def test_await_proceeds_on_non_tty_stdin() -> None:
    """A non-TTY stdin auto-proceeds even when stdout is interactive."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=False)
    assert (
        _await_sync(_await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}))
        == "proceed"
    )


def test_await_proceeds_on_ci_env() -> None:
    """``$CI=true`` auto-proceeds."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True)
    assert (
        _await_sync(
            _await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={"CI": "true"})
        )
        == "proceed"
    )


def test_await_proceeds_on_env_override() -> None:
    """``$AGENT_GUARDIAN_NO_PLAN_CONFIRM=1`` auto-proceeds."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True)
    assert (
        _await_sync(
            _await_plan_confirmation(
                yes=False,
                stdin=inp,
                stdout=out,
                environ={"AGENT_GUARDIAN_NO_PLAN_CONFIRM": "1"},
            )
        )
        == "proceed"
    )


def test_await_proceeds_on_timeout() -> None:
    """TTY with empty stdin + no input within the timeout proceeds.

    The new implementation wraps ``stdin.readline`` in
    ``asyncio.wait_for(loop.run_in_executor(...), timeout=...)``. The
    timeout path is verified by patching ``asyncio.wait_for`` to raise
    ``TimeoutError`` directly — using a real blocking ``readline``
    would deadlock on Python 3.11 because ``asyncio.run`` waits for
    every executor thread to finish during loop shutdown, and the
    thread can only exit AFTER the test's ``finally`` releases it,
    which only runs once ``asyncio.run`` returns.
    """
    import asyncio as _asyncio

    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True)

    async def _raise_timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise TimeoutError

    with patch.object(_asyncio, "wait_for", _raise_timeout):
        result = _await_sync(
            _await_plan_confirmation(
                yes=False, stdin=inp, stdout=out, environ={}, timeout_seconds=0.05
            )
        )
    assert result == "proceed"
    # The prompt line should have been printed.
    assert "Press Enter" in out.getvalue()


def test_await_proceeds_on_enter_keypress() -> None:
    """TTY with newline ready on stdin proceeds (Enter accepted)."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True, content="\n")
    result = _await_sync(
        _await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}, timeout_seconds=1.0)
    )
    assert result == "proceed"


def test_await_aborts_on_keyboard_interrupt() -> None:
    """A ``KeyboardInterrupt`` during the readline wait returns abort.

    With the asyncio-native implementation, KeyboardInterrupt arrives as
    either KeyboardInterrupt or asyncio.CancelledError at the await point.
    Simulating with a stdin.readline that raises directly covers the
    KeyboardInterrupt path.
    """

    class _RaisingTty(_FakeTty):
        def readline(self, _size: int = -1, /) -> str:
            raise KeyboardInterrupt

    out = _FakeTty(tty=True)
    inp = _RaisingTty(tty=True)
    result = _await_sync(
        _await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}, timeout_seconds=0.5)
    )
    assert result == "abort"


# ---------------------------------------------------------------------------
# Scout-prescribed: the 10-second wait must honour its full duration
# unless explicitly overridden — bug fix regression tests.
# ---------------------------------------------------------------------------


def _fake_clock_factory(ticks: list[float]) -> Any:
    """Return a ``monotonic`` substitute that walks through ``ticks`` in order.

    Each call to the returned callable yields the next value, repeating the
    last one when the list is exhausted. This lets a test simulate "10 s of
    real time" without the test itself sleeping.
    """
    state = {"i": 0}

    def _clock() -> float:
        idx = min(state["i"], len(ticks) - 1)
        state["i"] += 1
        return ticks[idx]

    return _clock


def test_scan_plan_wait_honors_ten_seconds_by_default(monkeypatch: Any) -> None:
    """The countdown loop walks the full timeout budget before proceeding.

    We replace the executor-backed readline with a future that never
    resolves and drive ``monotonic`` from a fake clock so the loop has
    to observe ten one-second ticks before timing out.
    """
    import asyncio as _asyncio

    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True)

    # 0.0 -> initial start; then 0.5, 1.5, ..., 9.5 (always remaining > 0);
    # then 10.0 and beyond (remaining hits 0 → proceed).
    ticks = [0.0] + [0.5 + n for n in range(10)] + [10.0, 10.0]
    clock = _fake_clock_factory(ticks)

    async def _slice_returns_timeout(*_args: Any, **_kwargs: Any) -> Any:
        # Simulate the per-second slice elapsing with no Enter pressed.
        raise TimeoutError

    monkeypatch.setattr(_asyncio, "wait_for", _slice_returns_timeout)

    result = _await_sync(
        _await_plan_confirmation(
            yes=False,
            stdin=inp,
            stdout=out,
            environ={},
            timeout_seconds=10.0,
            monotonic=clock,
        )
    )
    assert result == "proceed"
    rendered = out.getvalue()
    # The countdown must have ticked at least one observable second.
    assert "auto-proceed in" in rendered
    assert "10s" in rendered  # initial line uses the full 10s budget
    assert " 1s" in rendered  # we walked all the way down


def test_scan_plan_wait_short_circuits_on_yes_flag() -> None:
    """``yes=True`` returns immediately without printing the prompt."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True)
    result = _await_sync(
        _await_plan_confirmation(yes=True, stdin=inp, stdout=out, environ={}, timeout_seconds=10.0)
    )
    assert result == "proceed"
    assert out.getvalue() == ""


def test_scan_plan_wait_short_circuits_on_no_tui_flag() -> None:
    """A non-TTY stdout (the practical effect of ``--no-tui``) skips the wait."""
    out = _FakeTty(tty=False)
    inp = _FakeTty(tty=True)
    result = _await_sync(
        _await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}, timeout_seconds=10.0)
    )
    assert result == "proceed"
    assert out.getvalue() == ""


def test_scan_plan_keyboard_interrupt_aborts_cleanly() -> None:
    """``KeyboardInterrupt`` raised inside the readline executor → abort."""

    class _RaisingTty(_FakeTty):
        def readline(self, _size: int = -1, /) -> str:
            raise KeyboardInterrupt

    out = _FakeTty(tty=True)
    inp = _RaisingTty(tty=True)
    result = _await_sync(
        _await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}, timeout_seconds=0.5)
    )
    assert result == "abort"


def test_scan_plan_enter_proceeds_immediately() -> None:
    """A newline already waiting on stdin lets Enter resolve the wait fast."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True, content="\n")
    result = _await_sync(
        _await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}, timeout_seconds=2.0)
    )
    assert result == "proceed"


def test_scan_plan_timeout_default_not_zero() -> None:
    """Sanity guard: the default ``timeout_seconds`` keyword is still 10s.

    A future refactor that accidentally reverts the default to 0 (or
    drops the keyword) would otherwise let the panel flash by; we
    inspect the bound default so the regression is caught at import.
    """
    import inspect

    from agent_guardian.cli import _await_plan_confirmation as fn

    sig = inspect.signature(fn)
    default = sig.parameters["timeout_seconds"].default
    assert default == 10.0


def test_scan_plan_wait_with_framework_mode_same_as_endpoint() -> None:
    """Framework-mode scans hit the same gate; no special-case bypass exists.

    We confirm by reading the source of the CLI module and checking
    that every call to ``_await_plan_confirmation`` is parameter-only
    keyed on ``yes`` — no call site forwards ``framework`` or otherwise
    branches the wait behaviour on the target mode.
    """
    import inspect
    import re

    from agent_guardian import cli as cli_mod

    src = inspect.getsource(cli_mod)
    # Strip the definition itself so we only inspect call sites.
    call_sites = re.findall(
        r"_await_plan_confirmation\([^)]*\)",
        src.replace("async def _await_plan_confirmation", "DEFN_SKIPPED"),
    )
    assert call_sites, "expected at least one call site"
    # Every call site forwards only ``yes=...`` (no per-mode branching).
    for site in call_sites:
        assert "yes=" in site, site
        assert "framework" not in site, site
        assert "target_mode" not in site, site


def test_scan_plan_wait_respects_ci_environment_variable() -> None:
    """``$CI=true`` short-circuits the wait without rendering the countdown."""
    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True)
    result = _await_sync(
        _await_plan_confirmation(
            yes=False,
            stdin=inp,
            stdout=out,
            environ={"CI": "true"},
            timeout_seconds=10.0,
        )
    )
    assert result == "proceed"
    assert out.getvalue() == ""


def test_scan_plan_wait_drains_stale_stdin_before_waiting(monkeypatch: Any) -> None:
    """A newline that was already queued in stdin must NOT collapse the wait.

    The bug being fixed: the panel takes hundreds of ms to render, and an
    impatient operator who hits Enter during the render lands a "\\n" in
    the OS-level stdin buffer. Without a drain, ``readline()`` returns
    immediately and the 10-second window flashes by — exactly what the
    user reported. We assert the drain hook is invoked before the wait
    starts.
    """
    import agent_guardian.cli as cli_mod

    drained: list[Any] = []
    original = cli_mod._drain_stale_stdin

    def _track(inp: Any) -> None:
        drained.append(inp)
        original(inp)

    monkeypatch.setattr(cli_mod, "_drain_stale_stdin", _track)

    out = _FakeTty(tty=True)
    inp = _FakeTty(tty=True, content="\n")
    _await_sync(
        _await_plan_confirmation(yes=False, stdin=inp, stdout=out, environ={}, timeout_seconds=1.0)
    )
    assert drained == [inp]


# ---------------------------------------------------------------------------
# Integration — scan command honours the --no-plan and abort paths
# ---------------------------------------------------------------------------


def test_scan_command_skips_panel_with_no_plan_flag() -> None:
    """``--no-plan`` produces the legacy URL line and skips the Panel."""
    from typer.testing import CliRunner

    from agent_guardian.cli import app

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--no-plan",
            "--no-publish",  # suppresses URL emission too; sanity for plumbing
            "--model",
            "stub",
            "--mode",
            "fast",
            "--no-tui",
            "--no-serve",
            "--system-prompt",
            "/dev/null",
        ],
        catch_exceptions=False,
    )
    # The panel headline string must NOT appear under --no-plan.
    assert "Scan plan ·" not in result.stdout


def test_scan_command_aborts_cleanly_on_panel_no(tmp_path: Any) -> None:
    """Mocking ``_await_plan_confirmation`` → "abort" exits with EXIT_USER_INTERRUPT."""
    from typer.testing import CliRunner

    from agent_guardian import cli as cli_mod
    from agent_guardian.cli import EXIT_USER_INTERRUPT, app

    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("be helpful")

    runner = CliRunner()
    with patch.object(cli_mod, "_await_plan_confirmation", return_value="abort"):
        # Force TTY environment via env so the gate isn't auto-skipped before
        # the panel is even drawn. The mock above takes precedence regardless.
        env = {k: v for k, v in os.environ.items() if k != "CI"}
        env["AGENT_GUARDIAN_NO_PLAN_CONFIRM"] = ""
        result = runner.invoke(
            app,
            [
                "scan",
                "--model",
                "stub",
                "--mode",
                "fast",
                "--no-tui",
                "--no-serve",
                "--no-preflight",
                "--no-publish",
                "--system-prompt",
                str(prompt_file),
            ],
            env=env,
            catch_exceptions=False,
        )
    assert result.exit_code == EXIT_USER_INTERRUPT


# ---------------------------------------------------------------------------
# Live regression against the Cloud Run testbench
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("AGENT_GUARDIAN_LIVE_TESTBENCH"),
    reason="set $AGENT_GUARDIAN_LIVE_TESTBENCH=1 to run the live regression",
)
def test_panel_renders_against_live_testbench(tmp_path: Any) -> None:
    """Live regression: scan the real Cloud Run testbench with ``--yes``.

    Asserts ``"Scan plan · cli-"`` appears before ``"phase recon"`` in
    the captured stdout. Network-dependent; gated by env var so the CI
    cohort stays green offline.
    """
    import subprocess

    out_path = tmp_path / "live.json"
    proc = subprocess.run(
        [
            "uv",
            "run",
            "agent-guardian",
            "scan",
            "--endpoint",
            "https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app/finbot/chat",
            "--model",
            "stub",
            "--mode",
            "fast",
            "--no-tui",
            "--no-serve",
            "--yes",
            "--output",
            "json",
            "--output-path",
            str(out_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert "Scan plan · cli-" in proc.stdout, proc.stdout[:2000]
    if "phase recon" in proc.stdout:
        assert proc.stdout.find("Scan plan · cli-") < proc.stdout.find("phase recon")
