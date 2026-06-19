"""Finding model — one aggregated vulnerability with nested per-turn Attempts.

Pre-rc29, a :class:`Finding` corresponded to a single per-turn judge verdict
record. rc29 (this redesign) flips the semantics: a Finding now aggregates
over the ``(probe_id, asi)`` key, and each per-turn record becomes an
:class:`~agent_guardian.models.attempt.Attempt` under it.

On-disk payloads written by pre-rc29 scans are tagged ``schema_version =
"finding-v1"`` by the model-validator below and wrapped in a synthetic
single-element ``attempts=[<self>]`` list so downstream consumers see a
consistent shape regardless of when the scan ran. New emits default to
``schema_version = "finding-v2"``. See ``docs/_design/finding-aggregation-redesign-2026-06.md``
for the full rationale.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.attempt import Attempt
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
    """Aggregated vulnerability record keyed by ``(probe_id, asi)`` (rc29).

    Pre-rc29 emitted one Finding per per-turn judge verdict. rc29 aggregates:
    each per-turn record becomes an :class:`Attempt` under a single Finding
    for the same ``(probe_id, asi)`` pair. ``Finding.confidence`` is the
    Wilson lower bound of ``success_count / attempt_count``; ``success`` is
    ``True`` iff at least one attempt landed.

    Legacy on-disk payloads (no ``schema_version`` field) round-trip through
    the model-validator at the bottom of this class: they are tagged
    ``schema_version="finding-v1"`` and wrapped in a synthetic single-element
    ``attempts=[<self>]`` so downstream consumers (scoring, dashboard, SARIF)
    see one consistent shape.
    """

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
    # rc37 HIGH-5 (#251) — per-finding mirror of the PanelJudge vote shape
    # ({seat_verdicts, seat_confidences, agreement_fraction, majority,
    # confidence}). ``None`` when the finding came through the single-judge
    # path or when the panel didn't run for this finding. With this field
    # report.json carries enough panel signal that downstream tooling can
    # distinguish a 3-0 from a 2-1 outcome without re-parsing events.jsonl.
    panel: dict[str, Any] | None = None

    # rc29 aggregation redesign. ``attempts`` is the per-turn breakdown the
    # operator can drill into in the dashboard. ``success_count`` is the
    # numerator of the Wilson-bound ``confidence``; ``attempt_count`` is the
    # denominator. ``schema_version`` distinguishes new aggregated emits
    # (``"finding-v2"``) from legacy per-turn records loaded from disk
    # (``"finding-v1"``, set by the model-validator below). See
    # ``docs/_design/finding-aggregation-redesign-2026-06.md`` §II.A.
    attempts: list[Attempt] = Field(default_factory=list)
    success_count: int = Field(default=0, ge=0)
    schema_version: Literal["finding-v1", "finding-v2"] = "finding-v2"

    # ``extra="ignore"`` so old serialized findings (which lack the v2 fields)
    # and forward-serialized ones round-trip without raising.
    model_config = ConfigDict(frozen=True, extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def _compat_legacy_reader(cls, data: Any) -> Any:
        """Tag pre-rc29 dict payloads as ``finding-v1`` and synthesise an Attempt.

        A pre-rc29 on-disk Finding (one record per turn) has no
        ``schema_version`` field, no ``success_count`` field, and no
        ``attempts`` list. Downstream consumers under rc29 assume those
        three things exist. This validator runs at parse time:

        * If the payload is already a :class:`Finding` instance, pass it
          through untouched (cls(**...) round-trips do not re-trigger v1
          tagging).
        * If the payload is a dict that lacks ``schema_version``, mark it
          ``"finding-v1"``, default ``success_count`` to ``1 if success
          else 0``, and wrap the single per-turn record into a
          one-element ``attempts=[<synth>]`` list keyed off the payload's
          own per-turn fields (id, probe_id, asi, attempt_count as the
          sequence, verdict_v2, confidence, success, ...). The synthetic
          Attempt preserves the legacy per-turn id verbatim so the audit
          trail does not change.
        * If the payload is a dict that already has ``schema_version``
          (either v1 or v2), trust it and only fill ``attempts`` /
          ``success_count`` defaults when absent.

        Direct constructor calls (``Finding(...)``) by the aggregator
        pass ``schema_version="finding-v2"`` explicitly and bypass the
        synthetic wrap.
        """
        if not isinstance(data, dict):
            return data

        existing_version = data.get("schema_version")
        if existing_version is None:
            # Legacy on-disk payload — tag, fill the new fields from the
            # per-turn record, and synthesise a single Attempt so the
            # rest of the framework can read v1 records through the v2
            # shape.
            data = dict(data)  # avoid mutating caller's dict
            data["schema_version"] = "finding-v1"
            success_flag = bool(data.get("success", False))
            if "success_count" not in data:
                data["success_count"] = 1 if success_flag else 0
            if "attempts" not in data or not data.get("attempts"):
                asi_val = data.get("asi") or data.get("asi_id")
                # ``asi`` arrives as either an ``AsiCategory`` enum (with
                # ``.value``) or a raw string; tolerate both without losing
                # the legacy id when the field is missing entirely.
                asi_str = getattr(asi_val, "value", None) or (
                    str(asi_val) if asi_val is not None else ""
                )
                # ``attempt_count`` on a v1 record was the turn number this
                # specific record landed on; use it verbatim as the synthetic
                # Attempt's ``sequence`` so the legacy ordering survives.
                seq_raw = data.get("attempt_count", 1)
                try:
                    seq = int(seq_raw)
                except (TypeError, ValueError):
                    seq = 1
                if seq < 1:
                    seq = 1
                created_at = data.get("created_at")
                synth: dict[str, Any] = {
                    "id": str(data.get("id") or "legacy"),
                    "probe_id": str(data.get("probe_id") or "legacy"),
                    "asi": asi_str or "ASI01",
                    "sequence": seq,
                    "verdict_v2": str(data.get("verdict_v2") or "exploited"),
                    "confidence": float(data.get("confidence", 0.0)),
                    "success": success_flag,
                    "trigger_prompt": data.get("trigger_prompt"),
                    "trigger_response": data.get("trigger_response"),
                    "evidence_types": list(data.get("evidence_types") or []),
                    "evidence_quote": str(data.get("evidence_quote") or ""),
                    "created_at": created_at,
                    "reproduced_n_of_m": data.get("reproduced_n_of_m"),
                    "pov_reliability": data.get("pov_reliability"),
                    "summary": str(data.get("summary") or ""),
                }
                data["attempts"] = [synth]
        else:
            # Already-tagged payload (v1 or v2). Only fill rc29 fields when
            # absent so a stale on-disk record without ``attempts`` /
            # ``success_count`` doesn't refuse to parse.
            if "attempts" not in data or "success_count" not in data:
                data = dict(data)
                data.setdefault("attempts", [])
                if "success_count" not in data:
                    data["success_count"] = 1 if bool(data.get("success", False)) else 0
        return data

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
        #
        # rc29 also exposes ``schema_version`` on the wire so v1 and v2
        # records are distinguishable on disk without re-deriving the tag
        # from the absence of fields.
        data = handler(self)
        if "asi" in data and "asi_id" not in data:
            data["asi_id"] = data["asi"]
        # schema_version is already serialised because it's a real field,
        # but defensively ensure it survives any future serializer that
        # might drop unknown defaults.
        if "schema_version" not in data:
            data["schema_version"] = self.schema_version
        return data
