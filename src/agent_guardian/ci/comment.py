"""Shared PR/MR comment renderer (CI/CD feature).

Every code-host poster (GitHub today; GitLab / Bitbucket later) posts the SAME
markdown body so the comment reads identically across platforms. The body is
keyed by a hidden HTML marker on its first line so a poster can find its own
previous comment and update-in-place rather than spamming a new comment on
every push.

Finding-supplied strings are HTML-escaped (the table embeds them in a Markdown
context that some renderers pass through to HTML) and PII/credential-scrubbed
via the shared :func:`agent_guardian.core.redact.redact_finding` helper, exactly
as the standalone Markdown report does.
"""

from __future__ import annotations

from html import escape as _html_escape

from agent_guardian.core.gate import GateResult
from agent_guardian.core.redact import redact_finding
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, humanise_band
from agent_guardian.reports.markdown import TOP_FINDINGS_DEFAULT, _rank

__all__ = ["MARKER", "render_comment"]

# The hidden marker the posters search for to find-and-update their own
# previous comment. It MUST be the first non-blank line of the body and must
# not change once shipped — an existing comment is matched by substring.
MARKER = "<!-- agentguardian-pr-marker:scan -->"

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
}


def _summary_line(scan: Scan) -> str:
    """One-line headline: AIVSS NN/100 (band), N findings, cost, elapsed."""
    # A non-authoritative scan must NOT quote an authoritative numeric AIVSS
    # (mirrors the Markdown report + CLI summary): show ``n/a`` instead.
    if scan.scoring_valid:
        aivss_label = f"{scan.aivss}/100 ({humanise_band(scan.band)})"
    else:
        aivss_label = "n/a (not evaluated)"
    n = len(scan.findings)
    return (
        f"**AIVSS {aivss_label}** "
        f"&nbsp;|&nbsp; {n} finding{'s' if n != 1 else ''} "
        f"&nbsp;|&nbsp; ${scan.cost_usd:.4f} "
        f"&nbsp;|&nbsp; {scan.duration_seconds:.1f}s"
    )


def _verdict_block(gate: GateResult) -> str:
    """The PASSED / FAILED verdict plus one bullet per failing reason."""
    if gate.passed:
        return "### Gate: PASSED\n"
    lines = ["### Gate: FAILED\n"]
    for reason in gate.reasons:
        lines.append(f"- {_html_escape(reason)}\n")
    return "".join(lines)


def _findings_table(findings: list[Finding], top_n: int) -> str:
    """A top-N findings table: severity, probe_id, ASI, short summary."""
    ranked = sorted(findings, key=_rank)[:top_n]
    if not ranked:
        return "_No findings — this scan came back clean._\n"
    lines = [
        f"#### Top {len(ranked)} findings\n",
        "| Severity | Probe | ASI | Summary |\n",
        "|----------|-------|-----|---------|\n",
    ]
    for finding in ranked:
        severity = _SEVERITY_LABEL.get(finding.severity, finding.severity.value)
        probe_id = _html_escape(finding.probe_id)
        asi = _html_escape(finding.asi.value)
        summary = _html_escape(finding.summary)
        lines.append(f"| {severity} | `{probe_id}` | `{asi}` | {summary} |\n")
    return "".join(lines)


def render_comment(
    scan: Scan, gate: GateResult, *, top_n: int = TOP_FINDINGS_DEFAULT, redact: bool = True
) -> str:
    """Render the shared CI comment body for ``scan`` and its ``gate`` verdict.

    The body always STARTS with :data:`MARKER` (the hidden find-by-marker key),
    then a heading, a one-line summary, the gate verdict, and a top-N findings
    table.
    """
    findings = [redact_finding(f, enabled=redact) for f in scan.findings]
    parts = [
        f"{MARKER}\n",
        f"## AgentGuardian scan `{scan.id}`\n",
        "\n",
        f"{_summary_line(scan)}\n",
        "\n",
        _verdict_block(gate),
        "\n",
        _findings_table(findings, top_n),
    ]
    return "".join(parts)
