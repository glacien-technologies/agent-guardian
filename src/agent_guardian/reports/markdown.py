"""Markdown report emitter (PRD §10.3, M13).

This format targets human eyeballs on GitHub / GitLab — issue comments, PR
descriptions, status checks. We keep the layout flat: header, summary
table, per-ASI section, and the top-five findings as collapsible details.

GitHub renders ``<details>`` blocks but trims them when too long; we keep
the top five so the comment stays compact.

Because the layout embeds finding text inside raw HTML (``<details>`` /
``<summary>``), finding-supplied strings are HTML-escaped so attacker-reflected
markup (e.g. a ``<script>`` in a summary) renders inert rather than executing
in a non-sanitising Markdown renderer. Finding text is also scrubbed of PII +
credential shapes via the shared
:func:`agent_guardian.core.redact.redact_finding` helper (on by default).
"""

from __future__ import annotations

from html import escape as _html_escape
from pathlib import Path
from typing import Any

from agent_guardian.core.redact import redact_finding
from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, colour_for_band

__all__ = ["TOP_FINDINGS_DEFAULT", "emit_markdown", "write_markdown"]

TOP_FINDINGS_DEFAULT = 5

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

_SEVERITY_BADGE = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW: "[LOW]",
}


def _rank(finding: Finding) -> tuple[int, float]:
    # Sort by severity then descending confidence (low number == higher priority).
    return (_SEVERITY_ORDER.get(finding.severity, 99), -finding.confidence)


def _badge_line(scan: Scan) -> str:
    band = scan.band.value
    colour = colour_for_band(scan.band)
    # A non-authoritative scan (stub evaluator / scoring_valid=False) must NOT
    # present an authoritative numeric AIVSS — the band is NOT_EVALUATED and the
    # number is meaningless (#1). Show ``n/a`` to mirror the CLI summary.
    aivss_label = f"{scan.aivss}/100" if scan.scoring_valid else "n/a (not evaluated)"
    return (
        f"**AIVSS** `{aivss_label}` "
        f"&nbsp;|&nbsp; **Band** `{band}` "
        f"({colour}) "
        f"&nbsp;|&nbsp; **Tier** `{scan.tier.value}` "
        f"&nbsp;|&nbsp; **Coverage** `{scan.coverage_grade}`"
    )


def _undertested_badge_line(scan: Scan) -> str:
    """A "thinly tested" notice when the scan annotated undertested categories.

    Empty string when there are no undertested categories so the markdown
    layout stays unchanged for ordinary scans (#46).
    """
    if not scan.undertested:
        return ""
    pretty = ", ".join(f"`{_html_escape(cat)}`" for cat in scan.undertested)
    return (
        "> **Thinly tested** — the following categor"
        f"{'y was' if len(scan.undertested) == 1 else 'ies were'} launched but "
        "exercised too thinly to read absence of findings as safety evidence: "
        f"{pretty}.\n"
    )


def _summary_table(scan: Scan) -> str:
    summary = scan.findings_summary()
    return (
        "| Severity | Count |\n"
        "|----------|------:|\n"
        f"| Critical | {summary['critical']} |\n"
        f"| High     | {summary['high']} |\n"
        f"| Medium   | {summary['medium']} |\n"
        f"| Low      | {summary['low']} |\n"
        f"| **Total** | **{sum(summary.values())}** |\n"
    )


def _asi_section(scan: Scan, findings: list[Finding]) -> str:
    grouped: dict[AsiCategory, list[Finding]] = {cat: [] for cat in AsiCategory}
    for finding in findings:
        grouped[finding.asi].append(finding)
    lines: list[str] = ["## Per-ASI breakdown\n"]
    lines.append("| ASI | Description | Score | Findings |\n")
    lines.append("|-----|-------------|------:|---------:|\n")
    for category in AsiCategory:
        score = scan.asi_scores.get(category, 100.0)
        findings = grouped[category]
        lines.append(
            f"| `{category.value}` | {asi_description(category)} "
            f"| {score:.1f} | {len(findings)} |\n"
        )
    return "".join(lines)


def _top_findings_section(findings: list[Finding], top_n: int) -> str:
    ranked = sorted(findings, key=_rank)[:top_n]
    if not ranked:
        return "## Top findings\n\n_No findings — this scan came back clean._\n"
    body: list[str] = [f"## Top {len(ranked)} findings\n"]
    for finding in ranked:
        # HTML-escape every finding-supplied string: the layout embeds them in
        # raw <details>/<summary>/<code> HTML, so a <script> in a summary must
        # render inert, not execute in a non-sanitising Markdown renderer.
        summary = _html_escape(finding.summary)
        probe_id = _html_escape(finding.probe_id)
        finding_id = _html_escape(finding.id)
        body.append(
            f"<details>\n"
            f"<summary>{_SEVERITY_BADGE[finding.severity]} "
            f"<code>{probe_id}</code> — {summary}</summary>\n\n"
            f"- **ASI:** `{finding.asi.value}` "
            f"({asi_description(finding.asi)})\n"
            f"- **CSA:** `{finding.csa_category.value}`\n"
            f"- **MITRE ATLAS:** "
            f"{', '.join(f'`{t}`' for t in finding.mitre_atlas)}\n"
            f"- **Confidence:** {finding.confidence:.2f} "
            f"&nbsp;|&nbsp; **Attempts:** {finding.attempt_count} "
            f"&nbsp;|&nbsp; **Success:** {finding.success}\n"
            f"- **Finding ID:** `{finding_id}`\n"
            f"</details>\n"
        )
    return "\n".join(body) + "\n"


# RoE / contract audit keys mirrored into the Markdown report so the human
# artifact carries the same provenance as the signed JSON / SARIF.
_AUDIT_SUMMARY_KEYS = (
    ("contract_sha256", "Contract SHA-256"),
    ("contract_version", "Contract version"),
    ("authorization_ref", "Authorization ref"),
    ("environment", "Environment"),
    ("suppressed_tool_attempts", "Suppressed tool attempts"),
    ("egress_refused_turns", "Egress-refused turns"),
)


def _audit_section(audit: dict[str, Any]) -> str:
    rows = [(label, audit.get(key)) for key, label in _AUDIT_SUMMARY_KEYS]
    present = [(label, value) for label, value in rows if value is not None]
    if not present:
        return ""
    lines = ["## Rules of Engagement / Audit\n\n", "| Field | Value |\n", "|-------|-------|\n"]
    for label, value in present:
        lines.append(f"| {label} | `{_html_escape(str(value))}` |\n")
    return "".join(lines)


def emit_markdown(scan: Scan, *, top_n: int = TOP_FINDINGS_DEFAULT, redact: bool = True) -> str:
    """Render a Markdown report string for ``scan``."""
    findings = [redact_finding(f, enabled=redact) for f in scan.findings]
    parts = [
        f"# AgentGuardian scan `{scan.id}`\n",
        f"{_badge_line(scan)}\n",
        f"- **Target:** `{scan.target_ref}` ({scan.target_mode})\n",
        f"- **Duration:** {scan.duration_seconds:.2f}s "
        f"&nbsp;|&nbsp; **Cost:** ${scan.cost_usd:.4f}\n",
        f"- **Probe library:** `{scan.probe_library_version}` "
        f"&nbsp;|&nbsp; **AIVSS formula:** `{scan.aivss_formula_version}`\n",
        f"- **Generated:** `{scan.created_at.isoformat()}`\n",
    ]
    undertested_notice = _undertested_badge_line(scan)
    if undertested_notice:
        parts.append("\n")
        parts.append(undertested_notice)
    parts.extend(
        [
            "\n## Severity summary\n\n",
            _summary_table(scan),
            "\n",
            _asi_section(scan, findings),
            "\n",
            _top_findings_section(findings, top_n),
        ]
    )
    if scan.audit is not None:
        audit_md = _audit_section(scan.audit)
        if audit_md:
            parts.append("\n")
            parts.append(audit_md)
    return "".join(parts)


def write_markdown(
    scan: Scan, path: Path, *, top_n: int = TOP_FINDINGS_DEFAULT, redact: bool = True
) -> None:
    """Write the Markdown report for ``scan`` to ``path`` (UTF-8)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(emit_markdown(scan, top_n=top_n, redact=redact), encoding="utf-8")
