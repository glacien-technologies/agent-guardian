"""Finding model — one attack attempt with its judge verdict."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.mitre import MitreTechnique
from agent_guardian.models.severity import Severity

__all__ = ["Finding"]


class Finding(BaseModel):
    """Single attack-attempt record with its judge verdict (PRD §5)."""

    id: str = Field(min_length=1)
    probe_id: str = Field(min_length=1)
    asi: AsiCategory
    mitre_atlas: list[MitreTechnique] = Field(min_length=1)
    csa_category: CsaCategory
    severity: Severity
    attempt_count: int = Field(ge=1)
    success: bool
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1)
    transcript_ref: str | None = None
    created_at: datetime

    model_config = ConfigDict(frozen=True, extra="forbid")
