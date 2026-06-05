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
    # M2 Pattern 2 — the attack prompt that produced this finding, so the PoV
    # runner can faithfully replay it. ``None`` for findings whose trigger was
    # not captured (then the PoV gate keeps them ungated rather than dropping
    # something it cannot reproduce).
    trigger_prompt: str | None = None
    # M2 Pattern 2 — PoV-as-oracle. ``pov_reference`` points at the reproducer
    # script (e.g. ``pov/<finding_id>.py`` inside the bundle) and
    # ``pov_reliability`` is the N-fold rerun success rate (Wilson-lower-bounded
    # in the runner). Both ``None`` for v1 findings produced before the PoV
    # harness; the Commander drops findings whose reliability falls below the
    # gate before SARIF emission.
    pov_reference: str | None = None
    pov_reliability: float | None = Field(default=None, ge=0.0, le=1.0)
    created_at: datetime
    # Judge v2 (M0) — the v2 six-value verdict string that produced this
    # finding (``Finding.success`` stays the binary scoring projection via
    # ``verdict_to_success``; these are additive context, never read by
    # ``core/scoring.py``). ``trigger_response`` carries the (capped) target
    # reply that proves the compromise so the evidence is self-contained;
    # ``evidence_types`` names the corroboration signals (e.g. ``observable``,
    # ``tool_trace``) for later milestones.
    verdict_v2: str | None = None
    trigger_response: str | None = None
    evidence_types: list[str] = Field(default_factory=list)

    # ``extra="ignore"`` so old serialized findings (which lack the v2 fields)
    # and forward-serialized ones round-trip without raising.
    model_config = ConfigDict(frozen=True, extra="ignore")
