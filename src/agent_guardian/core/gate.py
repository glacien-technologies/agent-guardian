"""Pure CI-gate decision logic (CI/CD feature).

A scan can fail a CI gate for two independent reasons:

* the numeric AIVSS dropped below ``--fail-under``, or
* the count of findings in some severity band exceeded its ``--max-<sev>``
  ceiling (``--max-critical`` / ``--max-high`` / ``--max-medium`` / ``--max-low``).

Both are AND-combined: any failing condition fails the whole gate. A scan that
is *not authoritative* (stub evaluator, non-FULL mode, or otherwise
``scoring_valid=False`` / ``mode_authoritative=False``) can never pass a gate —
its numeric AIVSS reflects how much was tested, not how safe the agent is — so
the gate fails closed regardless of the thresholds (preserving the historical
``--fail-under`` behaviour in the ``scan`` command).

This module is deliberately free of any Typer / I/O dependency so the gate
decision is unit-testable in isolation and reusable by both the ``scan``
enforcement path and the ``comment`` sub-command (so the comment verdict
matches what the gate actually did).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_guardian.models.scan import Scan

__all__ = ["GateResult", "evaluate_gate"]


@dataclass(frozen=True)
class GateResult:
    """Outcome of a CI-gate evaluation against a single :class:`Scan`.

    ``reasons`` carries one human-readable line per failing condition (empty
    when the gate passed). ``counts`` is the scan's findings-by-severity
    roll-up so callers can render it without re-deriving it.
    """

    passed: bool
    reasons: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def evaluate_gate(
    scan: Scan,
    *,
    fail_under: int | None = None,
    max_critical: int | None = None,
    max_high: int | None = None,
    max_medium: int | None = None,
    max_low: int | None = None,
    mode_authoritative: bool | None = None,
) -> GateResult:
    """Decide whether ``scan`` passes the configured CI gate.

    Args:
        scan: The scan to evaluate.
        fail_under: Fail if the numeric AIVSS is strictly below this value.
        max_critical: Fail if the critical-finding count exceeds this value.
        max_high: Fail if the high-finding count exceeds this value.
        max_medium: Fail if the medium-finding count exceeds this value.
        max_low: Fail if the low-finding count exceeds this value.
        mode_authoritative: Override for whether the scan's mode is treated as
            authoritative. ``None`` (default) reads ``scan.mode_authoritative``.

    Returns:
        A :class:`GateResult`. ``passed`` is ``True`` only when the scan is
        authoritative AND every configured threshold is satisfied.
    """
    counts = scan.findings_summary()
    reasons: list[str] = []

    authoritative = scan.scoring_valid
    effective_mode_authoritative = (
        scan.mode_authoritative if mode_authoritative is None else mode_authoritative
    )

    # A non-authoritative scan never passes a gate: its numeric AIVSS reflects
    # how much was tested, not how safe the agent is (a stub evaluator can
    # never flag a finding). Fail closed and say why.
    if not authoritative:
        reasons.append(
            "scan is non-authoritative (NOT_EVALUATED) -- a stub/unscored run never passes a gate"
        )
    elif not effective_mode_authoritative:
        reasons.append(
            f"scan was run in --mode {scan.mode}; its quoted score "
            f"{scan.aivss} is not authoritative -- re-run with --mode full for "
            "a real gate"
        )

    # Numeric AIVSS floor. Only meaningful for an authoritative scan; for a
    # non-authoritative one the failure above already stands.
    if (
        fail_under is not None
        and authoritative
        and effective_mode_authoritative
        and scan.aivss < fail_under
    ):
        reasons.append(f"AIVSS {scan.aivss} is below --fail-under {fail_under}")

    # Per-severity finding-count ceilings.
    for label, ceiling in (
        ("critical", max_critical),
        ("high", max_high),
        ("medium", max_medium),
        ("low", max_low),
    ):
        if ceiling is None:
            continue
        observed = counts.get(label, 0)
        if observed > ceiling:
            reasons.append(f"{observed} {label} finding(s) exceed --max-{label} {ceiling}")

    return GateResult(passed=not reasons, reasons=reasons, counts=counts)
