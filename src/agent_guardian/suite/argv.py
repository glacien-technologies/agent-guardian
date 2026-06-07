"""Render a resolved workload into a real ``agent-guardian scan`` argv vector.

Every mapping here is verified against the live ``scan`` Typer signature in
``cli.py`` (flag spellings matter — a wrong name would silently change scan
behavior). Orchestration-only fields (``name`` / ``env`` / ``timeout_seconds`` /
``workdir`` / ``formats``) are NOT scan flags and never appear in argv.
"""

from __future__ import annotations

from agent_guardian.suite.schema import WorkloadFields

# Always appended so a child can never contend for the dashboard port, the Rich
# Live/stdout owner, the plan-confirm wait, or open a browser. The suite owns
# all of that; children are strictly headless. Verified flag spellings: there is
# NO ``--no-plan`` flag — ``--yes`` is what skips the plan-confirm wait.
FORCED_HEADLESS_FLAGS: tuple[str, ...] = (
    "--no-serve",
    "--no-tui",
    "--yes",
    "--no-publish",
    "--no-open",
)

# field name -> scan option flag (value-bearing options)
_VALUE_FLAGS: dict[str, str] = {
    "system_prompt": "--system-prompt",
    "endpoint": "--endpoint",
    "framework": "--framework",
    "framework_ref": "--framework-ref",
    "contract": "--contract",
    "model": "--model",
    "commander_model": "--commander-model",
    "attacker_model": "--attacker-model",
    "evaluator_model": "--evaluator-model",
    "mode": "--mode",
    "tier": "--tier",
    "goal": "--goal",
    "seed": "--seed",
    "max_turns": "--max-turns",
    "budget_usd": "--budget-usd",
    "budget_seconds": "--budget-seconds",
    "recon_budget_seconds": "--recon-budget-seconds",
    "fail_under": "--fail-under",
    "max_critical": "--max-critical",
    "max_high": "--max-high",
    "max_medium": "--max-medium",
    "max_low": "--max-low",
    "otel_endpoint": "--otel-endpoint",
}

# field name -> bare flag, emitted only when the field is True
_BOOL_FLAGS: dict[str, str] = {
    "no_owasp_llm": "--no-owasp-llm",
    "no_preflight": "--no-preflight",
    "pov_gate": "--pov-gate",
    "critic": "--critic",
    "pretext": "--pretext",
    "indirect": "--indirect",
    "log_agent_io": "--log-agent-io",
}


def build_scan_argv(workload: WorkloadFields) -> list[str]:
    """Return ``["scan", <positional?>, <flags...>, <forced headless...>]``."""
    argv: list[str] = ["scan"]

    # Target mode: ``target`` is a positional argument; the rest are options.
    if workload.target is not None:
        argv.append(workload.target)

    for field, flag in _VALUE_FLAGS.items():
        value = getattr(workload, field)
        if value is not None:
            argv.extend([flag, str(value)])

    for field, flag in _BOOL_FLAGS.items():
        if getattr(workload, field) is True:
            argv.append(flag)

    # The child always writes report.json natively; the aggregator renders any
    # extra requested formats from the same finished scan (never a second scan).
    argv.extend(["--output", "json"])

    argv.extend(FORCED_HEADLESS_FLAGS)
    return argv
