"""Scan model — top-level result for a single AgentGuardian run."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier

__all__ = ["BudgetReport", "Scan", "ScanCompleteness"]


class BudgetReport(BaseModel):
    """USD budget outcome for a scan.

    ``cap_usd`` is ``None`` for an uncapped run (we still report ``spent_usd``).
    ``finalise_truncated`` flags that the finalise phase hit the hard ceiling
    and skipped remaining paid work (PoV-gate / critic).
    """

    cap_usd: float | None = None
    spent_usd: float = Field(default=0.0, ge=0.0)
    pct_of_cap: float | None = None
    soft_stop_fraction: float = Field(default=0.80, ge=0.0, le=1.0)
    finalise_truncated: bool = False

    model_config = ConfigDict(frozen=True, extra="forbid")


class ScanCompleteness(BaseModel):
    """How much of the planned attack work actually ran.

    Lets a budget-stopped (partial) scan be read honestly: ``pct`` is the
    headline ``agents_completed / agents_planned`` figure.
    """

    agents_planned: int = Field(default=0, ge=0)
    agents_completed: int = Field(default=0, ge=0)
    agents_cut_short: int = Field(default=0, ge=0)
    turns_used: int = Field(default=0, ge=0)
    turns_planned: int = Field(default=0, ge=0)
    pct: float = Field(default=100.0, ge=0.0, le=100.0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class Scan(BaseModel):
    """Final scan result: AIVSS, sub-scores, findings, runtime metadata."""

    id: str = Field(min_length=1)
    package_version: str
    aivss_formula_version: str
    probe_library_version: str
    target_mode: Literal["prompt", "code", "http", "framework"]
    target_ref: str
    # Recon's inferred intent + how the profile was derived (recon redesign).
    # Optional so fixtures predating profiling still construct.
    target_inferred_goal: str | None = None
    target_profile_source: str | None = None
    tier: Tier
    aivss: int = Field(ge=0, le=100)
    band: SeverityBand
    sub_scores: dict[str, float]
    findings: list[Finding]
    asi_scores: dict[AsiCategory, float]
    duration_seconds: float = Field(ge=0.0)
    cost_usd: float = Field(ge=0.0)
    # Total tokens consumed (input + output) across attacker / evaluator /
    # commander / recon LLM calls. Aggregated from per-agent counters in
    # :meth:`SwarmCommander._phase_finalise`. Defaults to ``0`` for back-compat
    # with hand-constructed test fixtures that pre-date the cost-tracking
    # work (PRD §8.1 — IMPORTANT #3).
    tokens_total: int = Field(default=0, ge=0)
    # v1.1 — which scan-mode produced this report. ``"full"`` is the v1.1+
    # default; v1.0rc1 scans persist as ``"smart"`` for back-compat
    # (matches v1.0's actual behaviour). Defaults to ``"smart"`` here so
    # any older Scan JSON on disk continues to deserialise.
    mode: Literal["fast", "smart", "full"] = "smart"
    # Why the scan ended. ``"completed"`` is the normal full run; ``"budget"``
    # means the USD cap's soft-stop fired; ``"early_stop"`` is the variance
    # gate; ``"cancelled"`` is an operator cancel. Defaults keep older Scan
    # JSON deserialising.
    stopped_reason: Literal["completed", "budget", "early_stop", "cancelled"] = "completed"
    # Budget envelope outcome + how much of the planned work ran. Optional so
    # hand-built fixtures predating the runtime budget cap still construct.
    budget: BudgetReport | None = None
    completeness: ScanCompleteness | None = None
    created_at: datetime

    model_config = ConfigDict(frozen=True, extra="forbid")

    def findings_summary(self) -> dict[str, int]:
        """Count findings by severity. Keys: ``critical``, ``high``, ``medium``, ``low``."""
        summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            if finding.severity is Severity.CRITICAL:
                summary["critical"] += 1
            elif finding.severity is Severity.HIGH:
                summary["high"] += 1
            elif finding.severity is Severity.MEDIUM:
                summary["medium"] += 1
            elif finding.severity is Severity.LOW:
                summary["low"] += 1
        return summary
