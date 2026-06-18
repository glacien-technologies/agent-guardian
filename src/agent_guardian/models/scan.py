"""Scan model — top-level result for a single AgentGuardian run."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier

__all__ = ["BudgetReport", "CalibrationSummary", "Scan", "ScanCompleteness"]


class CalibrationSummary(BaseModel):
    """Brier-score calibration result for the judge(s) that produced this scan."""

    # WHY [0,1]: Brier is a mean-squared error of probabilities; outside [0,1] is malformed.
    brier_score: float = Field(ge=0.0, le=1.0)
    accuracy: float = Field(ge=0.0, le=1.0)
    n_items: int = Field(ge=0)
    judge_label: str = Field(min_length=1)
    # WHY optional: older calibration runs predate the version pin; new runs set it.
    calibration_set_version: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")


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
    # Issue #218 — per-agent termination breakdown. ``agents_cut_short``
    # gives the total count but not the cause distribution. Without this,
    # dashboard / SARIF coverage badges cannot distinguish "scan was
    # gracefully cancelled at the wall budget" (terminated_by=cancelled)
    # from "agent errored mid-flight" (terminated_by=error) or "agent
    # finished cleanly" (terminated_by=success). Keys are
    # ``TerminationReason`` values (success / cancelled / error / exhausted /
    # not_tested / early_stop); empty dict on back-compat reads.
    terminated_by_counts: dict[str, int] = Field(default_factory=dict)
    # Issue #260 — count of panel calls where EVERY seat raised before
    # producing a JudgeVerdict (panel collapsed, distinct from a real
    # unanimous ``needs_followup`` vote). The rc38 matrix shipped 441/441
    # panels in this state on a quota-exhausted key; pre-fix they were
    # indistinguishable from healthy unanimous panels in the report.
    # Default ``0`` keeps older Scan JSON on disk deserialising unchanged.
    errors_panel_all_errored: int = Field(default=0, ge=0)

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
    # Total probes attempted (loaded + dispatched) per ASI category. Used
    # by scoring as the denominator so 1 medium across 17 probes scores
    # ~98 instead of 60 (tester report #4). Empty dict for back-compat
    # with on-disk Scan JSON written before the field existed.
    probes_per_category: dict[AsiCategory, int] = Field(default_factory=dict)
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
    # (matches v1.0's actual behaviour). REQUIRED (no default): the swarm
    # commander always passes ``mode`` explicitly; hand-built fixtures must
    # therefore also be explicit so we never silently misreport a scan's
    # thoroughness profile (#4).
    mode: Literal["fast", "smart", "full"]
    # v1.1 — ``True`` when the scan's mode is FULL (the only mode whose
    # numeric AIVSS is intended to be quoted as authoritative). FAST/SMART
    # runs persist their numeric score for trend-tracking but ``--fail-under``
    # must refuse to gate-pass on them (the score reflects how much was
    # tested, not how safe the agent is). Defaults to ``True`` so older Scan
    # JSON on disk deserialises unchanged (#44).
    mode_authoritative: bool = True
    # Why the scan ended. ``"completed"`` is the normal full run; ``"budget"``
    # means the USD cap's soft-stop fired; ``"early_stop"`` is the variance
    # gate; ``"cancelled"`` is an operator cancel. Defaults keep older Scan
    # JSON deserialising.
    stopped_reason: Literal["completed", "budget", "early_stop", "cancelled"] = "completed"
    # Budget envelope outcome + how much of the planned work ran. Optional so
    # hand-built fixtures predating the runtime budget cap still construct.
    budget: BudgetReport | None = None
    completeness: ScanCompleteness | None = None
    # Stage 1B — contract provenance + RoE invocation envelope. A plain dict
    # (``AuditRecord.to_dict()`` payload) carrying ``contract_sha256``,
    # ``contract_version``, ``authorization_ref``, ``environment`` plus the
    # budget/tool-suppression counters surfaced into SARIF's invocation block.
    # Stored as a raw dict (not the model) so this module stays free of any
    # ``core.roe`` import — that would create an import cycle. Optional so
    # existing Scan construction + fixtures are unaffected.
    audit: dict[str, Any] | None = None
    # Provenance: which LLM specs drove the scan. Keys are the swarm roles
    # ``commander`` / ``attacker`` / ``evaluator`` mapping to a model id (e.g.
    # ``"openai:gpt-4o"`` or ``"stub"``). Folded into the signed report so an
    # auditor/leaderboard can tell a real assessment from a stub run. Optional
    # so existing Scan construction + fixtures predating provenance still build.
    engine: dict[str, str] | None = None
    # Whether the evaluator(s) that produced the verdicts were real LLMs. A
    # ``"stub"`` (canned-reply) evaluator can never flag a finding, so its
    # AIVSS=100/EXCELLENT is vacuous; ``"mixed"`` means some turns ran real and
    # some stub. The scoring phase sets ``scoring_valid=False`` for a stub run
    # and the report refuses a numeric EXCELLENT band (uses NOT_EVALUATED).
    evaluation_mode: Literal["real", "stub", "mixed"] = "real"
    # ``False`` marks a scan whose numeric AIVSS is NOT authoritative (stub
    # evaluator, or otherwise not a real assessment). ``--fail-under`` must
    # treat such a scan as a failure rather than a pass. Defaults ``True`` so
    # existing real-model scans + fixtures are unaffected.
    scoring_valid: bool = True
    # Issue #76 — attacker-quality provenance. ``attacker_rejection_rate`` is
    # the fraction of judged turns on which the attacker LLM produced no real
    # adversarial content (explicit refusal or stub/no-op) and the strategy fell
    # back to a static corpus seed. A high rate means the scan's adaptivity was
    # dampened by the attacker model's safety alignment, so the numeric AIVSS is
    # not authoritative even though the evaluator was real. ``attacker_active``
    # is ``False`` when no judged turn carried a real attack. Defaults keep older
    # Scan JSON deserialising (rate 0.0 / active True read as a healthy scan).
    attacker_rejection_rate: float = 0.0
    attacker_refused_turns: int = 0
    attacker_active: bool = True
    # v1.1 — ASI categories the scan launched but exercised so thinly that the
    # absence of findings is *not* evidence of safety: zero findings + fewer
    # than 5 judged turns + scan mode != FULL. Surfaced as a first-class
    # category state so dashboards / report renderers can say "thinly tested"
    # rather than letting an empty list read as "clean" (#46). Empty list for
    # scans without any undertested categories. Stored as a sorted list of the
    # raw ASI string values so the model stays JSON-round-trip safe.
    undertested: list[str] = Field(default_factory=list)
    # Issue #207 — ASI categories the swarm declared inapplicable to this
    # target (recon ruled the agent class out, e.g. ``a2a-agent`` skipped on
    # a non-a2a fingerprint, ``code-exec-agent`` skipped on a tool-less
    # target). ``asi_scores[cat]`` is held at 0.0 for the untested-is-not-
    # clean floor at the data layer, and the AIVSS aggregate already excludes
    # these via ``_tier_weighted_aggregate_excluding`` so the headline is
    # correct — but the per-ASI heatmap, markdown table, PDF, JUnit and JSON
    # renderers were reading ``asi_scores`` blindly and surfacing a deep-red
    # ``0`` next to (e.g.) "Agent Discovery / A2A" on a target where the
    # category was correctly skipped. Persisting ``never_launched`` lets
    # every renderer show **N/A** instead of a misleading 0. Sorted list of
    # raw ASI string values for JSON-round-trip safety; empty for back-compat
    # with older Scan JSON.
    never_launched: list[str] = Field(default_factory=list)
    # Issue #206 follow-up (rc35 deep-review M2 + L8) — recon-truncation
    # observability. ``recon_truncated`` is True when the recon phase hit
    # its wall-budget cap before producing a complete fingerprint, which
    # is the most common cause of an unexpectedly empty ``baseline_tools``
    # + a populated ``never_launched``. Without this signal, a CI consumer
    # reading ``never_launched=[ASI02,ASI04,ASI07,ASI10]`` cannot tell
    # whether those agent classes are genuinely out of scope on this
    # target (clean signal) or whether recon ran out of budget before
    # discovering them (scanner-side budget loss — a re-run with
    # ``--recon-budget-seconds`` may surface them). ``recon_completion_pct``
    # is ``measured_duration / cap_seconds`` clamped to [0, 100] so a
    # dashboard can render a progress meter on the recon phase. Both
    # default to safe values (``False`` / ``None``) so older Scan JSON
    # round-trips unchanged.
    recon_truncated: bool = False
    recon_completion_pct: float | None = Field(default=None, ge=0.0, le=100.0)
    # Issue #215 — commander planner outcome. ``"adaptive"`` when the
    # SwarmCommander LLM produced a per-agent plan; ``"uniform"`` when
    # the swarm fell back to the uniform brief (commander refused, parse
    # error, or LLM-call exception); ``None`` when the commander didn't
    # run at all (recon-only scan, or skipped by the "no operator or
    # inferred goal" gate -- issue #220 / L5). Without this signal an
    # operator auditing a non-authoritative scan cannot tell adaptive
    # from uniform without grep-ing run.log line-by-line. Default
    # ``None`` keeps back-compat with older Scan JSON on disk.
    planner_fallback: Literal["adaptive", "uniform"] | None = None
    # v1.1 — coverage grade summarising how thoroughly the swarm exercised
    # the target. ``A`` = every ASI category covered by real evidence;
    # ``F`` = no coverage at all. Persisted onto the Scan so an operator can
    # refuse a "100 / EXCELLENT" verdict on a scan whose coverage_grade is D
    # or worse. Defaults ``"A"`` so older Scan JSON on disk deserialises
    # unchanged.
    coverage_grade: Literal["A", "B", "C", "D", "F"] = "A"
    # C7 — judge calibration summary (Brier + accuracy). Optional so back-compat.
    calibration: CalibrationSummary | None = None
    created_at: datetime

    model_config = ConfigDict(frozen=True, extra="forbid")

    def findings_summary(self) -> dict[str, int]:
        """Count *confirmed* findings by severity. Keys: ``critical``, ``high``,
        ``medium``, ``low``.

        Only findings with ``success=True`` (an observable compromise — the
        judge's ``exploited`` verdict) are counted: informational findings
        (``success=False``, e.g. a ``vulnerable`` verdict where the guardrail
        slipped but no compromise was proven) must not inflate the severity
        counts a user trusts (#134). Use :meth:`informational_count` for the
        complement.
        """
        summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            if not finding.success:
                continue
            if finding.severity is Severity.CRITICAL:
                summary["critical"] += 1
            elif finding.severity is Severity.HIGH:
                summary["high"] += 1
            elif finding.severity is Severity.MEDIUM:
                summary["medium"] += 1
            elif finding.severity is Severity.LOW:
                summary["low"] += 1
        return summary

    def informational_count(self) -> int:
        """Number of informational (``success=False``) findings in ``findings``.

        These are unconfirmed observations (e.g. ``vulnerable`` /
        ``needs_followup`` verdicts, capability-exposure notes) retained for
        context. They are excluded from :meth:`findings_summary` and from
        AIVSS scoring (#134).
        """
        return sum(1 for finding in self.findings if not finding.success)
