"""CLI ``list-agents`` roster tests."""

from __future__ import annotations

from typer.testing import CliRunner

from agent_guardian.cli import app
from agent_guardian.core.swarm import expected_agent_count


def test_list_agents_includes_default_runtime_roster() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["list-agents"])

    assert result.exit_code == 0
    output = result.output
    expected_agents = (
        "recon-agent",
        "goal-hijack-agent",
        "tool-abuse-agent",
        "privilege-agent",
        "supply-chain-agent",
        "code-exec-agent",
        "memory-poison-agent",
        "a2a-agent",
        "cascade-agent",
        "trust-exploit-agent",
        "drift-agent",
        "identity-leak-agent",
        "fuzzing-agent",
        "secret-extraction-agent",
        "denial-of-wallet-agent",
        "detection-evasion-agent",
        "output-handling-agent",
    )

    rows = [
        line
        for line in output.splitlines()
        if any(line.startswith(agent_name) for agent_name in expected_agents)
    ]
    assert len(rows) == 1 + expected_agent_count(include_m2_agents=True)
    assert "eleven" not in output.lower()

    for agent_name in expected_agents:
        assert agent_name in output

    for agent_name in (
        "identity-leak-agent",
        "fuzzing-agent",
        "secret-extraction-agent",
        "denial-of-wallet-agent",
        "detection-evasion-agent",
        "output-handling-agent",
    ):
        assert agent_name in output

    assert "always-on" in output
    assert "default-on (--no-owasp-llm disables)" in output
