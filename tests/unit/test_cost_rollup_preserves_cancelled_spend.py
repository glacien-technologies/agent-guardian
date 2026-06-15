"""Issue #214 — cost_usd vs budget.spent_usd reconciliation.

The rc35 deep-review H4: ``cost_usd`` under-reports ``budget.spent_usd``
by 1.16x-1.69x when agents are cancelled. The deeper-research
investigation (PR-9 / R-1) traced this to a token-rollup leak on the
cancellation + error paths in ``SwarmCommander._run_agent_with_observer``:
the synthesised ``AgentReport`` was missing the ``tokens_consumed``
kwarg, so the cancelled agent's partial-turn spend silently dropped to
``{}``. Meanwhile ``budget.spent_usd`` (live meter via
``_live_cost_usd``) correctly picked it up — producing the divergence.

Empirical ratio scaling (1.16x for 1 cancelled, 1.69x for 3 cancelled,
linear with ``agents_cut_short``) confirmed the dropped-partial-turn-
spend hypothesis exactly.

The fix calls ``agent._snapshot_tokens()`` at the synthesis sites so
the cancelled / errored agent's partial-turn spend flows into the
``tokens_consumed`` dict the rollup reads from. This test locks the
contract so a future refactor can't drop the kwarg silently again.
"""

from __future__ import annotations

from agent_guardian.agents.base import AgentReport


def test_cancelled_agent_report_supports_tokens_consumed() -> None:
    """The cancellation-synthesis path constructs ``AgentReport(...,
    terminated_by='cancelled', tokens_consumed={'attacker_input': N,
    ...})``. The model must accept the kwarg; without it the cancelled
    agent's partial spend is silently zeroed."""
    report = AgentReport(
        agent="cancelled-test-agent",
        asi_category="ASI01",  # type: ignore[arg-type]
        findings_count=0,
        turns=0,
        duration_seconds=0.0,
        terminated_by="cancelled",
        notes="cancelled mid-run by outer wall-budget expiry",
        tokens_consumed={
            "attacker_input": 1500,
            "attacker_output": 400,
            "evaluator_input": 800,
            "evaluator_output": 200,
            "total": 2900,
        },
    )
    assert report.tokens_consumed["total"] == 2900
    assert report.terminated_by == "cancelled"


def test_errored_agent_report_supports_tokens_consumed() -> None:
    """Same contract for the generic-exception path."""
    report = AgentReport(
        agent="errored-test-agent",
        asi_category="ASI01",  # type: ignore[arg-type]
        findings_count=0,
        turns=0,
        duration_seconds=0.0,
        terminated_by="error",
        error="RuntimeError: simulated mid-turn failure",
        tokens_consumed={
            "attacker_input": 600,
            "attacker_output": 150,
            "total": 750,
        },
    )
    assert report.tokens_consumed["total"] == 750
    assert report.terminated_by == "error"
    assert "RuntimeError" in (report.error or "")


def test_cost_rollup_includes_cancelled_agent_partial_spend() -> None:
    """End-to-end shape: a finalise rollup that sums tokens_consumed
    across agent reports must pick up the cancelled agent's partial
    spend now that ``_run_agent_with_observer`` carries it through.

    This is the simplest reproduction of the rc35 H4 divergence shape:
    one cancelled agent with non-zero tokens_consumed must not silently
    contribute zero to the rollup.
    """
    cancelled_report = AgentReport(
        agent="dow-agent",
        asi_category="ASI08",  # type: ignore[arg-type]
        findings_count=0,
        turns=0,
        duration_seconds=0.0,
        terminated_by="cancelled",
        notes="cancelled mid-run by outer wall-budget expiry",
        tokens_consumed={
            "attacker_input": 2000,
            "attacker_output": 500,
            "evaluator_input": 1000,
            "evaluator_output": 250,
            "total": 3750,
        },
    )
    successful_report = AgentReport(
        agent="goal-hijack-agent",
        asi_category="ASI01",  # type: ignore[arg-type]
        findings_count=2,
        turns=4,
        duration_seconds=8.0,
        terminated_by="success",
        tokens_consumed={
            "attacker_input": 3000,
            "attacker_output": 700,
            "total": 3700,
        },
    )
    total = sum(r.tokens_consumed.get("total", 0) for r in (cancelled_report, successful_report))
    # rc35 H4: the buggy code path silently zeroed the cancelled report
    # so the rollup was 3700 (successful only). Post-fix: 7450.
    assert total == 7450, (
        f"cost rollup total = {total}; expected 7450 (3750 cancelled + 3700 "
        f"successful). A return to 3700 means the cancellation path dropped "
        f"the partial-turn spend again — the #214 H4 regression."
    )
