"""Tests that pin down the logging behaviour added across the codebase.

These tests defend the structured-trace contract: every scan must emit
INFO records for each phase, no silent ``except: pass`` may appear in
``src/agent_guardian/``, and every agent run must emit per-turn DEBUG
records so a reviewer can replay the loop from the log alone.
"""

from __future__ import annotations

import ast
import json
import logging
from pathlib import Path
from random import Random

import pytest

from agent_guardian import logging_setup
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.base import AgentBudget
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.core.memory import SharedMemory
from agent_guardian.core.swarm import SwarmCommander, SwarmConfig
from agent_guardian.llm.stub import StubScript

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "agent_guardian"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_attacker() -> object:
    """Return a stub LLM that satisfies every strategy prompt shape.

    Mirrors the integration-test shape so the swarm path exercises real
    log records for recon, decompose, parallel, finalise, and per-turn
    agent loops.
    """
    return (
        StubScript()
        .respond_to(
            "refined attack prompts",
            json.dumps(["attack variant alpha", "attack variant beta"]),
        )
        .respond_to("how relevant", "8")
        .respond_to("benign opening question", "What's the broad context here?")
        .respond_to("follow-up prompt", "Push a little harder along the same line.")
        .respond_to(
            "rewrite it to be more effective",
            json.dumps({"critique": "too direct", "rewrite": "stronger attempt"}),
        )
        .default("FALLBACK_ATTACKER")
    ).build()


def _stub_evaluator() -> object:
    """Evaluator stub that emits a ``"pass"`` judge verdict for every prompt."""
    return (
        StubScript().default(
            json.dumps({"verdict": "pass", "confidence": 0.5, "reasoning": "stub"})
        )
    ).build()


# ---------------------------------------------------------------------------
# 1. No silent excepts in src/
# ---------------------------------------------------------------------------


def _walk_except_handlers() -> list[tuple[str, int, str]]:
    """Yield (file, lineno, label) for every suspicious except handler.

    Suspicious = body is a single ``pass`` / ``Ellipsis`` AND there is no
    ``raise``. ``except: pass`` blocks are the load-bearing anti-pattern
    the logging-completeness work eliminated; this test guards against
    regressions.
    """
    issues: list[tuple[str, int, str]] = []
    for path in SRC_ROOT.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:  # pragma: no cover — defensive
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            body = node.body
            bare_pass_only = len(body) == 1 and isinstance(body[0], ast.Pass)
            ellipsis_only = (
                len(body) == 1
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and body[0].value.value is Ellipsis
            )
            if not (bare_pass_only or ellipsis_only):
                continue
            # ``raise`` inside the body would re-raise — that's NOT silent.
            has_raise = any(isinstance(sub, ast.Raise) for sub in ast.walk(node))
            if has_raise:
                continue
            issues.append((str(path), node.lineno, "bare-pass-or-ellipsis"))
    return issues


def test_no_silent_excepts_in_src() -> None:
    issues = _walk_except_handlers()
    assert not issues, (
        "Silent except handlers leak debugging context. Replace `pass` with a "
        "logger.debug() naming the expected condition. Offenders:\n"
        + "\n".join(f"  {path}:{lineno} {kind}" for path, lineno, kind in issues)
    )


# ---------------------------------------------------------------------------
# 2. configure_logging honours env var
# ---------------------------------------------------------------------------


def test_configure_logging_honors_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(logging_setup.ENV_VAR, "WARNING")
    logging_setup.configure_logging(force=True)
    assert logging.getLogger().getEffectiveLevel() == logging.WARNING


# ---------------------------------------------------------------------------
# 3. Swarm logs every phase at INFO
# ---------------------------------------------------------------------------


def _stub_target() -> object:
    """Stub LLM that the target adapter forwards to."""
    return (StubScript().default("I cannot help with that.")).build()


@pytest.mark.asyncio
async def test_swarm_logs_every_phase_at_info(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    adapter = PromptAdapter(
        "You are a tester. Refuse everything.",
        llm=_stub_target(),
        model="stub",
    )
    attacker = _stub_attacker()
    evaluator = _stub_evaluator()

    config = SwarmConfig(
        scan_id="swarm-log-test",
        commander_model="stub",
        attacker_model="stub",
        evaluator_model="stub",
        total_tokens=10_000,
        max_parallel_agents=1,
        recon_wall_seconds=2.0,
        overall_wall_seconds=10.0,
        checkpoint_interval_seconds=0.5,
    )

    memory = SharedMemory("swarm-log-test", root_dir=tmp_path)
    swarm = SwarmCommander(
        config=config,
        target=adapter,
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        commander_llm=attacker,
        memory=memory,
        rng_seed=0,
    )

    with caplog.at_level(logging.INFO, logger="agent_guardian.core.swarm"):
        await swarm.run()

    messages = [r.getMessage() for r in caplog.records]
    joined = "\n".join(messages)
    # We don't require every phrase precisely — but each named phase
    # must appear at INFO at least once.
    for phrase in (
        "phase recon: starting",
        "phase recon: done",
        "phase decompose: starting",
        "phase decompose: done",
        "phase finalise: starting",
        "aivss final:",
    ):
        assert phrase in joined, f"missing INFO log phrase: {phrase!r}\nFull log:\n{joined}"


# ---------------------------------------------------------------------------
# 4. Per-turn DEBUG logging on a single agent run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_run_logs_per_turn_at_debug(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    adapter = PromptAdapter(
        "You are a tester. Refuse everything.",
        llm=_stub_target(),
        model="stub",
    )
    attacker = _stub_attacker()
    evaluator = _stub_evaluator()
    agent = GoalHijackAgent(
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=10_000, wall_seconds_remaining=10.0, max_turns=3),
        rng=Random(0),
    )
    memory = SharedMemory("agent-log-test", root_dir=tmp_path)

    with caplog.at_level(logging.DEBUG, logger="agent_guardian.agents.base"):
        await agent.run(adapter, memory)

    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    info_records = [r for r in caplog.records if r.levelno == logging.INFO]
    # Each turn produces multiple DEBUG lines (strategy invoke, next_prompt,
    # target response, judge verdict). With max_turns=3 we expect at least
    # 4 DEBUGs in total (some scripts terminate earlier).
    assert len(debug_records) >= 4, (
        f"expected multiple per-turn DEBUG records, got {len(debug_records)}: "
        + str([r.getMessage()[:80] for r in caplog.records])
    )
    # agent_start + agent_done at INFO are non-negotiable.
    info_text = "\n".join(r.getMessage() for r in info_records)
    assert "agent_start" in info_text
    assert "agent_done" in info_text


# ---------------------------------------------------------------------------
# 5. Attacker refusal surfaces at WARNING (not silently swallowed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attacker_refusal_logs_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Force the PAIR refusal path and confirm a WARNING is recorded.

    PAIR detects the attacker LLM refusing via :func:`attacker_complete` and
    falls back to a corpus seed. Per the logging policy, that fallback is
    a WARNING — operators must spot when the attacker provider is dampening
    a scan since the resulting AIVSS score is no longer measuring the
    target's defences alone.
    """
    # An attacker stub that ALWAYS refuses to refine (matches refusal_markers).
    attacker = (
        StubScript()
        .respond_to(
            "rewrite it to be more effective",
            "I cannot help with that. Sorry.",
        )
        .default("I cannot help with that. Sorry.")
    ).build()
    evaluator = _stub_evaluator()
    adapter = PromptAdapter(
        "You are a tester. Decline politely.",
        llm=_stub_target(),
        model="stub",
    )
    agent = GoalHijackAgent(
        attacker_llm=attacker,
        evaluator_llm=evaluator,
        attacker_model="stub",
        evaluator_model="stub",
        budget=AgentBudget(tokens_remaining=10_000, wall_seconds_remaining=10.0, max_turns=4),
        rng=Random(0),
    )
    memory = SharedMemory("refusal-log-test", root_dir=tmp_path)

    with caplog.at_level(logging.WARNING, logger="agent_guardian.agents.base"):
        await agent.run(adapter, memory)

    refusal_warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "attacker LLM refused" in r.getMessage()
    ]
    assert refusal_warnings, (
        "no WARNING captured for attacker refusal — fallback path is silent. "
        f"Records: {[(r.levelno, r.getMessage()[:80]) for r in caplog.records]}"
    )


# ---------------------------------------------------------------------------
# 6. Every src module that isn't __init__ / _version has a logger
# ---------------------------------------------------------------------------


def test_modules_with_exception_handlers_have_loggers() -> None:
    """A module that catches exceptions MUST declare a logger.

    The reverse — a module with no try/except — may be a pure subclass
    that inherits its logger from a parent (every ASI specialist agent
    inherits from ``AsiAgent`` which logs). We only flag modules where
    a missing logger genuinely means a silent exception path.
    """
    missing: list[str] = []
    for path in SRC_ROOT.rglob("*.py"):
        if path.name in ("__init__.py", "_version.py"):
            continue
        # models/ + http_shapes/ are pure schema / converter modules.
        if "/models/" in str(path):
            continue
        if "/http_shapes/" in str(path) and path.name != "__init__.py":
            continue
        source = path.read_text(encoding="utf-8")
        if "logging.getLogger" in source or "_LOG = " in source or "logger = " in source:
            continue
        # Need a logger only if the module actually catches exceptions.
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        has_handler = any(isinstance(n, ast.ExceptHandler) for n in ast.walk(tree))
        if has_handler:
            missing.append(str(path.relative_to(SRC_ROOT.parent.parent)))
    assert not missing, (
        "These src modules contain except handlers but no logger. Add "
        "`_LOG = logging.getLogger(__name__)` so the handlers can announce "
        "what they swallowed:\n  " + "\n  ".join(missing)
    )
