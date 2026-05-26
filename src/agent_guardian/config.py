"""Configuration loader for the AgentGuardian CLI (PRD §8.2, M10).

The CLI reads settings from four sources, in descending precedence:

1. Explicit CLI flags (``--model``, ``--tier``, ``--budget-usd``…).
2. Environment variables (``AGENT_GUARDIAN_*``).
3. A YAML config file (``.agentguardian.yaml`` in cwd or
   ``~/.agentguardian/config.yaml``, or an explicit ``--config`` path).
4. The defaults baked into the :class:`Config` model.

This module owns the file + env layers; the CLI layer applies the flag
overrides on top. The :class:`Config` model is intentionally permissive —
missing sections silently fall back to defaults, so a user can start
with an empty YAML file and grow into the schema.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Config",
    "OutputConfig",
    "ServerConfig",
    "SwarmBudgetConfig",
    "SwarmConfig",
    "TargetConfig",
    "TelemetryConfig",
    "default_config_path",
    "discover_config_path",
    "load_config",
]


class SwarmBudgetConfig(BaseModel):
    """Wall-clock and token caps for one scan."""

    wall_seconds: int = Field(default=900, ge=1)
    max_total_tokens: int = Field(default=2_000_000, ge=1)
    model_config = ConfigDict(extra="forbid")


class SwarmConfig(BaseModel):
    """Swarm-level knobs — model identifiers and budget."""

    commander_model: str = "claude-haiku-4-5"
    attacker_model: str = "gpt-4o-mini"
    evaluator_model: str = "gpt-4o-mini"
    max_parallel_agents: int = Field(default=11, ge=1, le=11)
    budget: SwarmBudgetConfig = Field(default_factory=SwarmBudgetConfig)
    model_config = ConfigDict(extra="forbid")


class TargetConfig(BaseModel):
    """Target-side knobs — which mode + an optional tier override."""

    mode: Literal["prompt", "code", "http", "framework"] = "prompt"
    path: str | None = None
    endpoint: str | None = None
    framework: str | None = None
    tier: Literal["T1", "T2", "T3", "T4"] | None = None
    model_config = ConfigDict(extra="forbid")


class OutputConfig(BaseModel):
    """Output knobs — formats, redaction, signing."""

    formats: list[str] = Field(default_factory=lambda: ["json"])
    redact_pii: bool = True
    sign_evidence: bool = True
    output_dir: str | None = None
    model_config = ConfigDict(extra="forbid")


class ServerConfig(BaseModel):
    """Dashboard (M12) server defaults — placeholder shape today."""

    host: str = "127.0.0.1"
    port: int = Field(default=7474, ge=1, le=65_535)
    model_config = ConfigDict(extra="forbid")


class TelemetryConfig(BaseModel):
    """Opt-in usage telemetry (M15) — disabled by default."""

    enabled: bool = False
    model_config = ConfigDict(extra="forbid")


class Config(BaseModel):
    """Top-level CLI configuration model.

    All sections have sensible defaults; missing sections instantiate
    their default sub-model. Extra keys at any level raise so typos in a
    user's YAML surface early.
    """

    swarm: SwarmConfig = Field(default_factory=SwarmConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Discovery + loading
# ---------------------------------------------------------------------------


def default_config_path() -> Path:
    """Return the canonical user-level config path: ``~/.agentguardian/config.yaml``."""
    return Path.home() / ".agentguardian" / "config.yaml"


def discover_config_path(explicit: Path | None = None) -> Path | None:
    """Resolve which config file (if any) should be loaded.

    Order:

    1. The explicit path passed via ``--config``.
    2. ``.agentguardian.yaml`` in the current working directory.
    3. ``~/.agentguardian/config.yaml``.
    """
    if explicit is not None:
        return explicit
    cwd_candidate = Path.cwd() / ".agentguardian.yaml"
    if cwd_candidate.is_file():
        return cwd_candidate
    user_candidate = default_config_path()
    if user_candidate.is_file():
        return user_candidate
    return None


def _read_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if text.strip() else {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"config file {path} must contain a YAML mapping at the top level")
    return data


def load_config(path: Path | None = None) -> Config:
    """Load the AgentGuardian config from disk (or return defaults).

    If ``path`` is ``None`` we walk the discovery chain. A missing file
    returns the default :class:`Config` so the CLI works out of the box.
    """
    resolved = discover_config_path(path)
    if resolved is None or not resolved.is_file():
        return Config()
    data = _read_yaml(resolved)
    return Config.model_validate(data)


# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------


def env_api_key(provider: str) -> str | None:
    """Look up the ``AGENT_GUARDIAN_<PROVIDER>_API_KEY`` env var."""
    return os.environ.get(f"AGENT_GUARDIAN_{provider.upper()}_API_KEY")
