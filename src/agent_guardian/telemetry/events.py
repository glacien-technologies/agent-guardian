"""Telemetry event models -- strict Pydantic allowlist.

The model classes here ARE the data contract. Anything not declared
on a model cannot be sent. ``extra="forbid"`` means a typo in a field
name raises at construction time rather than silently leaking a value.

Three event types are accepted by the v1 collector schema:

* :class:`ScanCompletedEvent` -- emitted by :class:`SwarmCommander` at
  the end of every scan, regardless of crash status.
* :class:`InstallEvent` -- emitted by the first-run prompt the first
  time a user opts in.
* :class:`ForgetEvent` -- emitted when the user runs
  ``agent-guardian telemetry reset`` or revokes consent; tells the
  server to drop the install_id's row.

The :class:`ProbeFireEvent` is reserved for v1.1 (per-probe attribution
is one of the 6 optional metrics, behind a second toggle).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "TELEMETRY_SCHEMA_VERSION",
    "EventEnvelope",
    "ForgetEvent",
    "InstallEvent",
    "ProbeFireEvent",
    "ScanCompletedEvent",
    "TerminationKind",
]


TELEMETRY_SCHEMA_VERSION = 1
"""Bumped only on breaking schema changes. The collector accepts the
current version and (per Standard §9.4 dual-write window) the previous
version for 30 days after a bump."""


TerminationKind = Literal["success", "error", "crash"]
"""Three terminal scan states for crash-rate aggregation.

- ``success`` -- scan finalised cleanly, AIVSS computed.
- ``error`` -- scan completed but a non-crashing error path fired
  (e.g. judge LLM rate-limited so a verdict defaulted).
- ``crash`` -- uncaught exception in the swarm or scoring path.
  This is the only state that decrements the crash-free rate.
"""


class _Base(BaseModel):
    """Pydantic config shared by every event. Extra fields are rejected."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ScanCompletedEvent(_Base):
    """One scan finished. Sent once per scan by the orchestrator.

    The model is split into ESSENTIAL fields (always sent unless the
    user has fully opted out) and EXTENDED fields (only sent when
    the user has explicitly upgraded to the extended tier).

    The ESSENTIAL set is the four counts the user asked for --
    agents fired, attempts tried, successes (derived from
    pass-verdicts), threats captured (findings) -- plus the minimal
    context needed to make those counts meaningful (AIVSS, band,
    tier, duration, crash status, anonymous IDs, agent version).
    Crucially these do NOT include any environment fingerprint;
    they cannot identify the user, their machine, or their code.

    The EXTENDED set adds adapter name, Python version, OS family,
    and CPU arch -- fields useful for the compatibility-matrix
    dashboard cells but which constitute environment fingerprinting.
    """

    event_type: Literal["scan_completed"] = "scan_completed"
    schema_version: int = TELEMETRY_SCHEMA_VERSION

    # -- ESSENTIAL -- anonymous identifiers
    install_id: str = Field(min_length=36, max_length=36)  # UUID4
    scan_id: str = Field(min_length=8, max_length=64)  # local-random, anonymous

    # -- ESSENTIAL -- operational result (the four counts the user asked for)
    aivss: int = Field(ge=0, le=100)
    band: Literal["EXCELLENT", "GOOD", "WARNING", "POOR", "CRITICAL"]
    tier: Literal["T1", "T2", "T3", "T4"]
    # v1.1 -- scan thoroughness mode. ESSENTIAL because it's purely
    # operational (which preset ran) -- it carries no identifying or
    # environmental information about the user, and the collector needs
    # it to bucket crash-rate / coverage stats by mode (FAST scans
    # legitimately find fewer things; we shouldn't conflate them with
    # FULL scans in dashboards). Defaults to "smart" so events emitted
    # by clients still on v1.0 deserialise without breaking the
    # collector's strict-allowlist contract.
    mode: Literal["fast", "smart", "full"] = "smart"
    duration_seconds: float = Field(ge=0.0)
    terminated_by: TerminationKind
    agents_count: int = Field(ge=0, default=0)
    """Number of AsiAgent instances that actually ran (recon + specialists, minus skipped)."""
    attempts_count: int = Field(ge=0, default=0)
    """Total per-turn judged events across all agents. Was 68 in the verification scan."""
    successes_count: int = Field(ge=0, default=0)
    """Per-turn pass verdicts -- attempts where the target defended successfully."""
    findings_total: int = Field(ge=0)
    findings_critical: int = Field(ge=0)
    findings_high: int = Field(ge=0)
    findings_medium: int = Field(ge=0)
    findings_low: int = Field(ge=0)

    # -- ESSENTIAL -- release attribution (needed for crash-by-version)
    agent_version: str = Field(min_length=1, max_length=64)

    # -- ESSENTIAL -- timestamps for time-window bucketing
    started_at: datetime
    completed_at: datetime

    # -- EXTENDED -- environment fingerprint. ``None`` when the user is
    # only on the ESSENTIAL tier; populated when they've explicitly
    # upgraded via ``agent-guardian telemetry extended``.
    adapter: (
        Literal[
            "prompt",
            "code",
            "http",
            "framework",
            "langgraph",
            "adk",
            "crewai",
            "openai-agents",
            "autogen",
            "strands",
            "custom",
        ]
        | None
    ) = None
    target_mode: Literal["prompt", "code", "http", "framework"] | None = None
    python_version: str | None = Field(default=None, pattern=r"^3\.\d{1,2}$")
    os_family: Literal["Linux", "Darwin", "Windows"] | None = None
    arch: Literal["x86_64", "arm64", "aarch64", "i686"] | None = None
    # -- EXTENDED -- which LLM drove the scan, as a ``provider:model`` id
    # (e.g. ``gemini:gemini-2.5-flash``, ``bedrock:us.anthropic.claude-...``).
    # This is the attacker/driver model spec with all ``+qualifiers``
    # STRIPPED upstream (the emitter normalises via ``parse_model_spec``),
    # so identifying qualifiers like ``+base_url=`` / ``+project=`` /
    # ``+endpoint=`` / ``+region=`` never reach the wire. The pattern bars
    # whitespace and URL query chars as a second line of defence. Answers
    # "which models/providers do people scan with" at provider+model
    # granularity without fingerprinting the user.
    model: str | None = Field(default=None, max_length=128, pattern=r"^[a-zA-Z0-9._:/-]+$")


class InstallEvent(_Base):
    """First-time install event, emitted by the opt-in prompt.

    Triggers when the user picks "yes" in the first-run prompt -- NOT
    on every package install. The collector uses this to derive MAU
    by joining against scan_completed.install_id.
    """

    event_type: Literal["install"] = "install"
    schema_version: int = TELEMETRY_SCHEMA_VERSION

    install_id: str = Field(min_length=36, max_length=36)
    agent_version: str = Field(min_length=1, max_length=64)
    python_version: str = Field(pattern=r"^3\.\d{1,2}$")
    os_family: Literal["Linux", "Darwin", "Windows"]
    arch: Literal["x86_64", "arm64", "aarch64", "i686"]
    opted_in_at: datetime


class ProbeFireEvent(_Base):
    """One probe fired during one scan. v1.1 -- gated behind the
    'extended diagnostics' toggle.

    Reserved here so the schema is stable from v1.0; the client does
    not emit these by default in v1.0.
    """

    event_type: Literal["probe_fire"] = "probe_fire"
    schema_version: int = TELEMETRY_SCHEMA_VERSION

    install_id: str = Field(min_length=36, max_length=36)
    scan_id: str = Field(min_length=8, max_length=64)
    probe_id: str = Field(min_length=1, max_length=64)
    asi_category: Literal[
        "ASI01",
        "ASI02",
        "ASI03",
        "ASI04",
        "ASI05",
        "ASI06",
        "ASI07",
        "ASI08",
        "ASI09",
        "ASI10",
    ]
    severity: Literal["critical", "high", "medium", "low"]
    fired_at: datetime


class ForgetEvent(_Base):
    """User revoked consent. Tells the collector to drop this install_id.

    Sent once when the user opts out. Best-effort -- if the network call
    fails the local state is still cleared, and a future retry layer
    can resend. The user's intent (opt out) is honoured locally
    immediately regardless of network state.
    """

    event_type: Literal["forget"] = "forget"
    schema_version: int = TELEMETRY_SCHEMA_VERSION

    install_id: str = Field(min_length=36, max_length=36)
    opted_out_at: datetime


class EventEnvelope(_Base):
    """Wrapper sent over the wire. One envelope = one event.

    The envelope adds a ``client_sent_at`` timestamp so the collector
    can detect clock skew (Standard §4 of the analytics PRD: drop events
    where ``client_sent_at`` is >30 days past or >5 minutes future).
    """

    client_sent_at: datetime
    event: ScanCompletedEvent | InstallEvent | ProbeFireEvent | ForgetEvent = Field(
        discriminator="event_type",
    )
