"""Finding model — one attack attempt with its judge verdict."""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_serializer

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.mitre import MitreTechnique
from agent_guardian.models.severity import Severity

__all__ = ["Finding"]


def _wilson_lower_bound(successes: int, trials: int) -> float:
    # Inlined mirror of ``agent_guardian.core.pov.runner.wilson_lower_bound``
    # so this leaf model module stays free of ``core``-layer imports (the full
    # ``core/__init__.py`` pulls in ``models.scan`` which would cycle back
    # through this file). Honest about small N: 1/2 → ~0.09, 5/5 → ~0.57.
    if trials <= 0:
        return 0.0
    z = 1.96
    phat = successes / trials
    denom = 1.0 + z * z / trials
    centre = phat + z * z / (2 * trials)
    margin = z * math.sqrt((phat * (1.0 - phat) + z * z / (4 * trials)) / trials)
    return max(0.0, (centre - margin) / denom)


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
    # Issue #76 (C1) — the judge's verbatim quoted span that justified this
    # verdict (the exact `force_wire_transfer({...})` / `drop_table({...})`
    # trace line or the leaked value), so the highest-severity findings are
    # independently auditable from the report instead of storing only the prose
    # ``trigger_response``. Empty when the judge surfaced no quotable span.
    evidence_quote: str = ""
    # Issue #76 (D1) — FULL-mode repeat-trial consistency: ``"<reproduced>/<n>"``
    # (e.g. ``"3/3"``) records how many of N independent re-runs of this exact
    # trigger reproduced a successful verdict. OWASP red-teaming treats a 1/1
    # success as weaker evidence than 3/3. ``None`` = no repeat-trial was run
    # (LITE/FAST or non-success verdict), which reads as the legacy single pass.
    reproduced_n_of_m: str | None = None
    # Issue #76 (D3) — what a secure target SHOULD have done with the probe that
    # produced this finding (refuse, require confirmation, verify authorization,
    # …), carried from the probe corpus. Makes the report self-explanatory:
    # alongside what happened (trigger_response / evidence_quote), the reader
    # sees what should have happened. ``None`` for probes without the metadata.
    expected_safe_behavior: str | None = None
    # #136 — cross-category de-duplication. When several ASI lanes elicited the
    # byte-identical target response, finalise keeps the finding in a single
    # owning category and folds the other categories in here (sorted ASI value
    # strings, e.g. ``["ASI03", "ASI10"]``) so the cross-lane signal survives
    # as a cross-reference instead of as duplicate findings with conflicting
    # severities. Empty for findings that were never deduplicated against.
    related_asi: list[str] = Field(default_factory=list)

    # ``extra="ignore"`` so old serialized findings (which lack the v2 fields)
    # and forward-serialized ones round-trip without raising.
    model_config = ConfigDict(frozen=True, extra="ignore")

    @property
    def pov_reliability_effective(self) -> float | None:
        # Issue #159 — single source of truth for "how repeatable is this
        # finding?", used by ``scoring._is_band_eligible``. Priority:
        # 1. Explicit ``pov_reliability`` (PoV-runner output, already
        #    Wilson-lower-bounded). Trusted as-is.
        # 2. Parsed ``reproduced_n_of_m`` as Wilson lower bound — so a 1/2 reads
        #    as ~0.09 rather than naive 0.5 (chance-level evidence shouldn't
        #    contribute to a band flip).
        # 3. ``None`` when neither was measured. Callers treat ``None`` as the
        #    legacy band-eligible path (don't accidentally drop pre-#159
        #    findings).
        if self.pov_reliability is not None:
            return self.pov_reliability
        if self.reproduced_n_of_m is None:
            return None
        try:
            successes_s, trials_s = self.reproduced_n_of_m.split("/", 1)
            successes = int(successes_s)
            trials = int(trials_s)
        except (ValueError, AttributeError):
            return None
        if trials <= 0 or successes < 0 or successes > trials:
            return None
        return _wilson_lower_bound(successes, trials)

    @model_serializer(mode="wrap")
    def _serialize_with_asi_id_alias(
        self, handler: Callable[[Finding], dict[str, Any]]
    ) -> dict[str, Any]:
        # Issue #159 — downstream consumers (SARIF emitter, dashboard, scan
        # property bag) read ``asi_id``; the model field is ``asi``. Emit both
        # keys with the same string value so neither consumer breaks while we
        # keep a single field of truth on the model.
        data = handler(self)
        if "asi" in data and "asi_id" not in data:
            data["asi_id"] = data["asi"]
        return data
