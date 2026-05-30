"""Authoritativeness-warning text builder (QA-004).

When a scan finishes ``scoring_valid=False`` the CLI surfaces a banner
explaining *why* the result is non-authoritative. Historically the banner
was a single hard-coded string that always blamed a stub / non-LLM
evaluator. That copy is correct for ``evaluation_mode="stub"`` but
nonsensical for ``evaluation_mode="real"`` runs whose only sin is thin
probe coverage — yet the same banner fired for both, telling users to
"re-run with a real --model" they had already supplied.

This module replaces that hard-coded string with a pure function that
branches on ``(evaluation_mode, coverage_pct, mode_threshold)`` and
returns the right copy — or ``None`` when the scan is authoritative and
no warning should be emitted at all.

The mode-threshold table :data:`MODE_AUTHORITATIVE_THRESHOLDS` is the
single source of truth shared with :class:`SwarmCommander` (the producer
of ``scoring_valid``) and the CLI coverage-warning emitter — see the
"single source of truth" note in QA-004's DESIGN_LOCK §F-3.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal

from agent_guardian.models.scan import Scan

__all__ = [
    "MODE_AUTHORITATIVE_THRESHOLDS",
    "WARNING_LOW_COVERAGE_TEMPLATE",
    "WARNING_MIXED_TEMPLATE",
    "WARNING_STUB_TEMPLATE",
    "build_authoritativeness_warning",
]


# ---------------------------------------------------------------------------
# Mode-threshold table (single source of truth).
# ---------------------------------------------------------------------------

ScanModeStr = Literal["fast", "smart", "full"]

#: Minimum-coverage percentage at which a scan in the given mode is allowed
#: to keep ``scoring_valid=True``. Below the threshold finalise downgrades
#: the band to NOT_EVALUATED and the warning copy below explains why.
#:
#: These values match :class:`agent_guardian.core.swarm.SwarmCommander`'s
#: ``_MIN_AUTHORITATIVE_COMPLETENESS`` table — both sites import from here so
#: a future calibration change happens in exactly one place.
MODE_AUTHORITATIVE_THRESHOLDS: Mapping[ScanModeStr, float] = MappingProxyType(
    {
        "fast": 60.0,
        "smart": 80.0,
        "full": 95.0,
    }
)


# When the user is already in the smallest mode, the "drop to <smaller>"
# remediation in the low-coverage template is replaced with the budget-only
# remediation. The mapping is exhaustive over :data:`MODE_AUTHORITATIVE_THRESHOLDS`
# so a future ``ScanMode`` addition will not silently fall through.
_SMALLER_MODE: Mapping[ScanModeStr, ScanModeStr | None] = MappingProxyType(
    {
        "full": "smart",
        "smart": "fast",
        "fast": None,  # already the smallest mode
    }
)


# ---------------------------------------------------------------------------
# Warning copy.
# ---------------------------------------------------------------------------
#
# The three branches are intentionally kept as module-level format strings so
# the unit tests can snapshot-match each branch and so a future localisation
# pass has one obvious place to swap.

WARNING_STUB_TEMPLATE = (
    "WARNING: this scan is NON-AUTHORITATIVE. "
    "evaluation_mode=stub "
    "(engine: attacker={attacker}, evaluator={evaluator}). "
    "A stub / non-LLM evaluator cannot flag findings, so the numeric AIVSS "
    "is meaningless and the band is reported as NOT_EVALUATED. "
    "Re-run with a real --model (e.g. openai:gpt-4o, "
    "anthropic:claude-haiku-4-5, gemini:gemini-2.5-flash) for an "
    "authoritative assessment."
)


WARNING_LOW_COVERAGE_TEMPLATE = (
    "WARNING: this scan is NON-AUTHORITATIVE. "
    "evaluation_mode=real "
    "(engine: attacker={attacker}, evaluator={evaluator}). "
    "Coverage {coverage_pct:.0f}% is below the --mode {mode} authoritative "
    "threshold ({threshold:.0f}%). {findings_count} findings were flagged "
    "but the underlying probe coverage is too thin for a band call. "
    "{remediation}"
)


WARNING_MIXED_TEMPLATE = (
    "WARNING: this scan is NON-AUTHORITATIVE. "
    "evaluation_mode=mixed "
    "(engine: attacker={attacker}, evaluator={evaluator}). "
    "The swarm ran some agents with a real LLM evaluator and some with the "
    "stub fallback. Mixed-evaluator scans cannot produce an authoritative "
    "band call. Re-run with a single real --model across attacker + "
    "evaluator for a full-fidelity assessment."
)


# Remediation phrasings for the low-coverage branch — exhaustive over modes.

_REMEDIATION_RAISE_BUDGET_OR_DROP_MODE = (
    "Re-run with a larger --budget-usd or --budget-seconds, or drop to "
    "--mode {smaller_mode} for a faster authoritative pass."
)

_REMEDIATION_RAISE_BUDGET_ONLY = (
    "Re-run with a larger --budget-usd or --budget-seconds (you are already "
    "on the smallest --mode, so a smaller mode is not available)."
)


# ---------------------------------------------------------------------------
# Public builder.
# ---------------------------------------------------------------------------


def build_authoritativeness_warning(scan: Scan) -> str | None:
    """Return the right NON-AUTHORITATIVE warning for *scan*, or ``None``.

    Branches:

    * ``scan.scoring_valid is True`` → ``None`` (authoritative; no banner).
    * ``evaluation_mode == "stub"`` → :data:`WARNING_STUB_TEMPLATE`.
    * ``evaluation_mode == "mixed"`` → :data:`WARNING_MIXED_TEMPLATE`.
    * ``evaluation_mode == "real"`` → low-coverage copy naming the actual
      coverage %, the active mode's authoritative threshold, the finding
      count, and an actionable remediation (raise budget, or drop a mode
      down when one is available).
    * Anything else (e.g. an ``evaluation_mode`` literal a future Scan
      revision adds that this code does not yet understand) falls back to
      the stub-style copy — the safe default that tells the user the scan
      is not trustworthy without inventing a diagnosis.

    The function is pure: no I/O, no logging, no globals beyond the
    module-level templates. Easy to unit-test, easy to snapshot.
    """
    if scan.scoring_valid:
        return None

    engine = scan.engine or {}
    attacker = engine.get("attacker", "?")
    evaluator = engine.get("evaluator", "?")

    if scan.evaluation_mode == "stub":
        return WARNING_STUB_TEMPLATE.format(attacker=attacker, evaluator=evaluator)

    if scan.evaluation_mode == "mixed":
        return WARNING_MIXED_TEMPLATE.format(attacker=attacker, evaluator=evaluator)

    if scan.evaluation_mode == "real":
        mode = scan.mode
        threshold = MODE_AUTHORITATIVE_THRESHOLDS.get(mode)
        if threshold is None:
            # Unknown mode literal — safe-default to stub copy so we never
            # claim a coverage diagnosis we cannot back up.
            return WARNING_STUB_TEMPLATE.format(attacker=attacker, evaluator=evaluator)

        coverage_pct = float(scan.completeness.pct) if scan.completeness is not None else 0.0
        smaller = _SMALLER_MODE[mode]
        if smaller is None:
            remediation = _REMEDIATION_RAISE_BUDGET_ONLY
        else:
            remediation = _REMEDIATION_RAISE_BUDGET_OR_DROP_MODE.format(
                smaller_mode=smaller,
            )

        return WARNING_LOW_COVERAGE_TEMPLATE.format(
            attacker=attacker,
            evaluator=evaluator,
            coverage_pct=coverage_pct,
            mode=mode,
            threshold=threshold,
            findings_count=len(scan.findings),
            remediation=remediation,
        )

    # Unknown / future evaluation_mode literal — safe-default.
    return WARNING_STUB_TEMPLATE.format(attacker=attacker, evaluator=evaluator)
