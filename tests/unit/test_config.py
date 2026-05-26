"""Unit tests for the CLI config loader (M10)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardian.config import (
    Config,
    OutputConfig,
    ServerConfig,
    SwarmBudgetConfig,
    SwarmConfig,
    TargetConfig,
    TelemetryConfig,
    default_config_path,
    discover_config_path,
    env_api_key,
    load_config,
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def test_config_defaults() -> None:
    cfg = Config()
    assert isinstance(cfg.swarm, SwarmConfig)
    assert isinstance(cfg.target, TargetConfig)
    assert isinstance(cfg.output, OutputConfig)
    assert isinstance(cfg.server, ServerConfig)
    assert isinstance(cfg.telemetry, TelemetryConfig)


def test_swarm_budget_defaults() -> None:
    b = SwarmBudgetConfig()
    assert b.wall_seconds == 900
    assert b.max_total_tokens == 2_000_000


def test_swarm_config_defaults() -> None:
    s = SwarmConfig()
    assert s.commander_model == "claude-haiku-4-5"
    assert s.attacker_model == "gpt-4o-mini"
    assert s.evaluator_model == "gpt-4o-mini"
    assert s.max_parallel_agents == 11


def test_target_config_defaults_to_prompt_mode() -> None:
    t = TargetConfig()
    assert t.mode == "prompt"
    assert t.path is None
    assert t.tier is None


def test_output_config_defaults_to_json() -> None:
    o = OutputConfig()
    assert o.formats == ["json"]
    assert o.redact_pii is True
    assert o.sign_evidence is True


def test_telemetry_disabled_by_default() -> None:
    t = TelemetryConfig()
    assert t.enabled is False


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def test_load_explicit_path(tmp_path: Path) -> None:
    yaml_path = tmp_path / "cfg.yaml"
    yaml_path.write_text(
        """\
swarm:
  commander_model: gpt-4o
  attacker_model: gpt-4o-mini
  evaluator_model: gpt-4o-mini
  budget:
    wall_seconds: 60
    max_total_tokens: 100000
""",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path)
    assert cfg.swarm.commander_model == "gpt-4o"
    assert cfg.swarm.budget.wall_seconds == 60
    assert cfg.swarm.budget.max_total_tokens == 100_000


def test_load_missing_path_returns_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = load_config(tmp_path / "absent.yaml")
    assert cfg.swarm.commander_model == "claude-haiku-4-5"


def test_load_empty_yaml_returns_defaults(tmp_path: Path) -> None:
    yaml_path = tmp_path / "empty.yaml"
    yaml_path.write_text("", encoding="utf-8")
    cfg = load_config(yaml_path)
    assert isinstance(cfg, Config)
    assert cfg.swarm.commander_model == "claude-haiku-4-5"


def test_load_rejects_non_mapping_yaml(tmp_path: Path) -> None:
    yaml_path = tmp_path / "list.yaml"
    yaml_path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(yaml_path)


def test_load_rejects_extra_keys(tmp_path: Path) -> None:
    from pydantic import ValidationError

    yaml_path = tmp_path / "bad.yaml"
    yaml_path.write_text("swarm:\n  surprise: yes\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(yaml_path)


def test_load_partial_yaml_keeps_defaults_for_missing_sections(tmp_path: Path) -> None:
    yaml_path = tmp_path / "partial.yaml"
    yaml_path.write_text("telemetry:\n  enabled: true\n", encoding="utf-8")
    cfg = load_config(yaml_path)
    assert cfg.telemetry.enabled is True
    # Other sections retain defaults.
    assert cfg.swarm.commander_model == "claude-haiku-4-5"


def test_load_full_yaml(tmp_path: Path) -> None:
    yaml_path = tmp_path / "full.yaml"
    yaml_path.write_text(
        """\
swarm:
  commander_model: claude-haiku-4-5
  attacker_model: gpt-4o-mini
  evaluator_model: gpt-4o-mini
  max_parallel_agents: 5
  budget:
    wall_seconds: 120
    max_total_tokens: 500000
target:
  mode: code
  path: ./my_agent.py:run
  tier: T2
output:
  formats: [json, sarif]
  redact_pii: false
  sign_evidence: false
server:
  host: 0.0.0.0
  port: 8080
telemetry:
  enabled: true
""",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path)
    assert cfg.swarm.max_parallel_agents == 5
    assert cfg.target.mode == "code"
    assert cfg.target.tier == "T2"
    assert cfg.output.formats == ["json", "sarif"]
    assert cfg.server.host == "0.0.0.0"
    assert cfg.telemetry.enabled is True


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discover_explicit_path_wins(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("swarm: {}", encoding="utf-8")
    found = discover_config_path(explicit)
    assert found == explicit


def test_discover_cwd_file_when_no_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    cwd_file = tmp_path / ".agentguardian.yaml"
    cwd_file.write_text("swarm: {}", encoding="utf-8")
    found = discover_config_path(None)
    assert found == cwd_file


def test_discover_returns_none_when_nothing_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    # Point HOME at a directory with no config.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    found = discover_config_path(None)
    assert found is None


def test_default_config_path_under_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    path = default_config_path()
    assert path == tmp_path / ".agentguardian" / "config.yaml"


# ---------------------------------------------------------------------------
# Env vars
# ---------------------------------------------------------------------------


def test_env_api_key_reads_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_OPENAI_API_KEY", "sk-test-123")
    assert env_api_key("openai") == "sk-test-123"


def test_env_api_key_returns_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    assert env_api_key("openai") is None


def test_env_api_key_uppercases_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", "ant-key")
    assert env_api_key("anthropic") == "ant-key"
