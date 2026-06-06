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
    # Per the operator "no arbitrary hardcoded caps" rule, wall_seconds
    # defaults to None (uncapped). Operators opt in to a cap via
    # --budget-seconds or by setting the field in their contract file.
    b = SwarmBudgetConfig()
    assert b.wall_seconds is None
    assert b.max_total_tokens == 10_000_000


def test_swarm_config_defaults() -> None:
    s = SwarmConfig()
    assert s.commander_model == "claude-haiku-4-5"
    assert s.attacker_model == "gemini-3.5-flash"
    assert s.evaluator_model == "gemini-3.5-flash"
    assert s.max_parallel_agents == 11
    # Cross-family judge panel is opt-in: default same-family panel keeps
    # scans buildable with one API key. Operators opt in by setting
    # judge_cross_family_enforced=True + a second-family evaluator_model.
    assert s.judge_cross_family_enforced is False


def test_swarm_budget_wall_seconds_default_is_uncapped() -> None:
    # The "no arbitrary hardcoded caps" rule: wall_seconds defaults to None.
    # Operators opt in to a cap via --budget-seconds on the CLI or by setting
    # cfg.swarm.budget.wall_seconds explicitly.
    b = SwarmBudgetConfig()
    assert b.wall_seconds is None


def test_target_config_defaults_to_prompt_mode() -> None:
    t = TargetConfig()
    assert t.mode == "prompt"
    assert t.path is None
    assert t.tier is None


def test_output_config_defaults_to_json() -> None:
    o = OutputConfig()
    assert o.formats == ["json"]
    # Redaction is opt-in (off by default) — mirrors the memory.jsonl and
    # report-emitter defaults. Operators asked to see verbatim target output.
    assert o.redact_pii is False
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
    # ``env_api_key`` falls back to the provider's standard env var
    # (``OPENAI_API_KEY``) when the namespaced one is unset (see
    # ``_STANDARD_ENV_VAR``). To exercise the "neither is set" branch we
    # must delete *both*. Process-level .env autoload + side-effects from
    # other tests can leave ``OPENAI_API_KEY`` populated, so this is a
    # correctness fix for the test, not a behaviour change.
    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert env_api_key("openai") is None


def test_env_api_key_uppercases_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", "ant-key")
    assert env_api_key("anthropic") == "ant-key"


# Standard-env-var fallback. Namespaced ``AGENT_GUARDIAN_*`` keys win when set;
# otherwise we fall back to the provider's conventional variable. GOOGLE_API_KEY
# is accepted as an alias for Gemini.


def test_env_api_key_prefers_namespaced_over_standard_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_OPENAI_API_KEY", "namespaced-key")
    monkeypatch.setenv("OPENAI_API_KEY", "standard-key")
    assert env_api_key("openai") == "namespaced-key"


def test_env_api_key_falls_back_to_standard_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-fallback")
    assert env_api_key("openai") == "openai-fallback"


def test_env_api_key_falls_back_to_standard_anthropic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-fallback")
    assert env_api_key("anthropic") == "anthropic-fallback"


def test_env_api_key_prefers_namespaced_gemini(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDIAN_GEMINI_API_KEY", "namespaced-gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "fallback-gemini")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-gemini")
    assert env_api_key("gemini") == "namespaced-gemini"


def test_env_api_key_falls_back_to_gemini_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_GUARDIAN_GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-fallback")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert env_api_key("gemini") == "gemini-fallback"


def test_env_api_key_google_api_key_alias_for_gemini(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GOOGLE_API_KEY is accepted as a fallback alias for Gemini."""
    monkeypatch.delenv("AGENT_GUARDIAN_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "google-fallback")
    assert env_api_key("gemini") == "google-fallback"


def test_env_api_key_gemini_prefers_gemini_api_key_over_google_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When both standard aliases are set, GEMINI_API_KEY wins."""
    monkeypatch.delenv("AGENT_GUARDIAN_GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-wins")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-loses")
    assert env_api_key("gemini") == "gemini-wins"


def test_env_api_key_returns_none_when_nothing_set_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for var in ("AGENT_GUARDIAN_OPENAI_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert env_api_key("openai") is None


def test_env_api_key_returns_none_when_nothing_set_gemini(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for var in (
        "AGENT_GUARDIAN_GEMINI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    assert env_api_key("gemini") is None


def test_env_api_key_unknown_provider_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Providers with no standard alias (e.g. bedrock) still resolve via the
    namespaced var, and otherwise return None."""
    monkeypatch.delenv("AGENT_GUARDIAN_BEDROCK_API_KEY", raising=False)
    assert env_api_key("bedrock") is None
    monkeypatch.setenv("AGENT_GUARDIAN_BEDROCK_API_KEY", "bk")
    assert env_api_key("bedrock") == "bk"


# ---------------------------------------------------------------------------
# QA-G23 (2026-06-03) — sign_evidence forward-compat placeholder
# ---------------------------------------------------------------------------


def test_load_config_warns_when_sign_evidence_is_set(tmp_path: Path) -> None:
    """Setting ``output.sign_evidence`` emits a one-shot ``DeprecationWarning``.

    The flag is a forward-compatibility placeholder — no downstream consumer
    reads it. ``load_config`` accepts it (existing configs do not break) but
    surfaces a deprecation warning so the operator knows the flag is a no-op
    until v1.1 Sigstore work lands.
    """
    yaml_path = tmp_path / "cfg.yaml"
    yaml_path.write_text("output:\n  sign_evidence: true\n", encoding="utf-8")
    with pytest.warns(DeprecationWarning, match="sign_evidence"):
        cfg = load_config(yaml_path)
    assert cfg.output.sign_evidence is True


def test_load_config_does_not_warn_when_sign_evidence_is_absent(
    tmp_path: Path, recwarn: pytest.WarningsRecorder
) -> None:
    """Configs that don't mention ``sign_evidence`` do not trigger the warning.

    The deprecation surface is opt-in: operators who never set the flag never
    see the noise. Only configs that explicitly set the flag receive the
    one-shot guidance message.
    """
    yaml_path = tmp_path / "cfg.yaml"
    yaml_path.write_text("swarm:\n  max_parallel_agents: 3\n", encoding="utf-8")
    load_config(yaml_path)
    sign_evidence_warnings = [w for w in recwarn.list if "sign_evidence" in str(w.message)]
    assert sign_evidence_warnings == []


def test_load_config_accepts_sign_evidence_false_without_raising(
    tmp_path: Path,
) -> None:
    """Explicit ``sign_evidence: false`` is still accepted (forward-compat).

    Deprecation must never break an existing config — the warning is the
    contract, not a refusal. ``load_config`` continues to round-trip the
    value through the ``OutputConfig`` model so the field is still
    introspectable from tests and downstream code.
    """
    yaml_path = tmp_path / "cfg.yaml"
    yaml_path.write_text("output:\n  sign_evidence: false\n", encoding="utf-8")
    with pytest.warns(DeprecationWarning, match="sign_evidence"):
        cfg = load_config(yaml_path)
    assert cfg.output.sign_evidence is False
