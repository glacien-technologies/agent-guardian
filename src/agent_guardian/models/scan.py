"""Scan model — top-level result for a single AgentGuardian run."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier

__all__ = ["Scan"]


class Scan(BaseModel):
    """Final scan result: AIVSS, sub-scores, findings, runtime metadata."""

    id: str = Field(min_length=1)
    package_version: str
    aivss_formula_version: str
    probe_library_version: str
    target_mode: Literal["prompt", "code", "http", "framework"]
    target_ref: str
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
