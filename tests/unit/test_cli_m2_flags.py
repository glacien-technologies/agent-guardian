"""Tests for the M2 CLI flags + OWASP-LLM agent dispatch wiring."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.cli import app
from agent_guardian.core.swarm import _ASI_AGENT_CLASSES, SwarmCommander, SwarmConfig
from agent_guardian.llm.stub import StubLLM, StubScript


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Chdir to an empty tmp dir + clear API-key vars so a CLI invocation can't
    load the repo's real .env into os.environ and pollute other tests."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    for var in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "AGENT_GUARDIAN_OPENAI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def test_m2_flags_in_scan_help() -> None:
    # Assert against the registered Typer options, not the rendered --help text:
    # Rich truncates long option names with an ellipsis at narrow widths (CI's
    # non-tty default), and honouring COLUMNS in the invoke env is version-
    # dependent. Introspecting the command params is environment-proof.
    from click import Group
    from typer.main import get_command

    cmd = get_command(app)
    assert isinstance(cmd, Group)
    scan = cmd.commands["scan"]
    registered = {opt for param in scan.params for opt in param.opts}
    for flag in (
        "--pov-gate",
        "--critic",
        "--bundle",
        "--pretext",
        "--indirect",
        # Post-launch hardening: the OWASP-LLM specialists now run by default;
        # the operator opts OUT with --no-owasp-llm rather than opting in.
        "--no-owasp-llm",
    ):
        assert flag in registered


def test_include_m2_agents_extends_the_slate() -> None:
    # Default: only the core ASI01-10 slate is decomposed.
    cfg_off = SwarmConfig(scan_id="off")
    assert cfg_off.include_m2_agents is False

    # When set, the swarm appends the 5 OWASP-LLM specialists
    # (LLM05 / LLM07 / LLM10 / detection-evasion / LLM02).
    from agent_guardian.agents import M2_SPECIALIST_AGENTS

    assert len(M2_SPECIALIST_AGENTS) == 5
    # Sanity: the M2 specialists are not already in the core slate.
    assert all(c not in _ASI_AGENT_CLASSES for c in M2_SPECIALIST_AGENTS)


@pytest.mark.asyncio
async def test_decompose_includes_m2_agents_when_flagged() -> None:
    target = PromptAdapter("test target", llm=StubScript().default("ok").build(), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(scan_id="m2", include_m2_agents=True, max_parallel_agents=14),
        target=target,
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
    )
    fp = target.fingerprint()
    agents = await swarm._phase_decompose(fp)
    names = {a.name for a in agents}
    # At least one M2 specialist is dispatched (applicability gates the rest).
    assert "fuzzing-agent" in names or "denial-of-wallet-agent" in names


@pytest.mark.asyncio
async def test_decompose_excludes_m2_agents_by_default() -> None:
    target = PromptAdapter("test target", llm=StubScript().default("ok").build(), model="stub")
    swarm = SwarmCommander(
        config=SwarmConfig(scan_id="core"),
        target=target,
        attacker_llm=StubLLM(default="ok"),
        evaluator_llm=StubLLM(default="ok"),
    )
    agents = await swarm._phase_decompose(target.fingerprint())
    names = {a.name for a in agents}
    assert "fuzzing-agent" not in names
    assert "secret-extraction-agent" not in names
