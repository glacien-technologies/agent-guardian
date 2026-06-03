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

import logging
import os
import warnings
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

_LOG = logging.getLogger(__name__)

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

    # wall_seconds defaults to None (uncapped) per the operator
    # "no arbitrary hardcoded caps" rule. Operators opt in to a wall-
    # clock cap via the CLI flag (--budget-seconds) or by setting this
    # field explicitly in the contract file.
    wall_seconds: int | None = Field(default=None, ge=1)
    max_total_tokens: int = Field(default=2_000_000, ge=1)
    model_config = ConfigDict(extra="forbid")


class SwarmConfig(BaseModel):
    """Swarm-level knobs — model identifiers and budget.

    Defaults to a single-family (Gemini) attacker + evaluator. Cross-
    family judge panel is opt-in via ``judge_cross_family_enforced``
    so a scan does not silently require a second provider's API key.
    Operators who want the cross-family panel set the toggle to True
    AND configure a second-family ``evaluator_model``.
    """

    commander_model: str = "claude-haiku-4-5"
    attacker_model: str = "gemini-3.5-flash"
    evaluator_model: str = "gemini-3.5-flash"
    max_parallel_agents: int = Field(default=11, ge=1, le=11)
    budget: SwarmBudgetConfig = Field(default_factory=SwarmBudgetConfig)
    judge_cross_family_enforced: bool = False
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
    """Output knobs — formats, redaction, signing.

    .. note:: ``sign_evidence`` is a **forward-compatibility placeholder**.

        It was originally intended to gate Sigstore-backed signing of the full
        evidence bundle, but that signing path is not implemented in 1.0 — it
        is targeted for v1.1. Setting the flag to ``True`` or ``False`` today
        is a no-op (every ``scan.json`` already ships Ed25519 + HMAC-SHA256
        signatures unconditionally, verifiable via ``agent-guardian verify``).

        We accept the flag in YAML for forward compatibility so existing
        operator configs do not break on upgrade; :func:`load_config` emits
        a single ``DeprecationWarning`` when it is present (see
        ``_warn_about_sign_evidence_if_set``). The field will be removed
        when the v1.1 Sigstore implementation lands and gives the flag real
        meaning, or repurposed to gate that implementation.
    """

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


def _warn_about_sign_evidence_if_set(raw_data: dict[str, Any], resolved: Path) -> None:
    """Emit a one-shot deprecation warning when ``output.sign_evidence`` is set.

    QA-G23 (2026-06-03): the flag has no downstream consumer in 1.0 — it was
    documented as "wired" in the README but is a placebo in both directions.
    Rather than silently accept-and-ignore (which breeds distrust in a
    security tool's other claims) or hard-fail on the field (which would
    break existing operator configs on upgrade), we accept it for forward
    compatibility and emit a single ``DeprecationWarning`` per load so the
    operator knows the flag is a no-op until the v1.1 Sigstore work lands.
    """
    output = raw_data.get("output")
    if not isinstance(output, dict):
        return
    if "sign_evidence" not in output:
        return
    msg = (
        f"output.sign_evidence in {resolved} is a forward-compatibility "
        "placeholder and has no effect in agent-guardian 1.0 — every scan.json "
        "is already Ed25519+HMAC signed unconditionally (verify with "
        "`agent-guardian verify <scan.json>`). Sigstore-backed evidence-bundle "
        "signing is planned for v1.1; the flag will gain effect there. You "
        "can remove it from your config today without changing any signing "
        "behaviour."
    )
    # Surface to both Python warnings (so test harnesses can catch with
    # ``pytest.warns(DeprecationWarning)``) and the logger (so JSON-log
    # SIEM consumers see it in production). Best-effort: a closed warnings
    # filter is not an error worth raising for a documentation flag.
    try:
        warnings.warn(msg, DeprecationWarning, stacklevel=3)
    except Exception as exc:  # pragma: no cover - defensive
        # The ``warnings`` module can raise (e.g. ``-W error::DeprecationWarning``
        # under pytest, or a malformed user filter). We never want a config-load
        # to crash on a documentation-only warning surface; debug-log the
        # condition so the test harness's no-silent-excepts policy is satisfied
        # without leaking the warning text twice into stderr.
        _LOG.debug(
            "deprecation warning emission for output.sign_evidence raised (%s: %s) — falling back to logger only",
            type(exc).__name__,
            exc,
        )
    _LOG.warning("deprecated_config_flag output.sign_evidence: %s", msg)


def load_config(path: Path | None = None) -> Config:
    """Load the AgentGuardian config from disk (or return defaults).

    If ``path`` is ``None`` we walk the discovery chain. A missing file
    returns the default :class:`Config` so the CLI works out of the box.
    """
    resolved = discover_config_path(path)
    if resolved is None or not resolved.is_file():
        return Config()
    data = _read_yaml(resolved)
    _warn_about_sign_evidence_if_set(data, resolved)
    return Config.model_validate(data)


# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------


# Provider → conventional env-var names to consult as a fallback when no
# namespaced ``AGENT_GUARDIAN_<PROVIDER>_API_KEY`` is set. Order matters:
# the first var with a value wins. ``GOOGLE_API_KEY`` is widely used as the
# Gemini AI Studio key and is accepted as an alias.
_STANDARD_ENV_VAR: dict[str, tuple[str, ...]] = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}


def env_api_key(provider: str) -> str | None:
    """Resolve a provider API key from the environment.

    Precedence:

    1. ``AGENT_GUARDIAN_<PROVIDER>_API_KEY`` — the namespaced variable. Users
       running multiple red-team tools side-by-side can keep their per-tool
       keys isolated this way.
    2. The provider's conventional env var(s) — ``OPENAI_API_KEY``,
       ``ANTHROPIC_API_KEY``, ``GEMINI_API_KEY``. For Gemini we also accept
       ``GOOGLE_API_KEY`` as an alias because that's what the Google AI
       Studio quickstart hands users.

    Returns ``None`` when neither is set, so callers can decide whether to
    error out (paid providers) or silently fall back (Ollama / stub).
    """
    namespaced = os.environ.get(f"AGENT_GUARDIAN_{provider.upper()}_API_KEY")
    if namespaced:
        return namespaced
    for var in _STANDARD_ENV_VAR.get(provider.lower(), ()):
        value = os.environ.get(var)
        if value:
            return value
    return None
