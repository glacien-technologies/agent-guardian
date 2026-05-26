"""Markdown report emitter (PRD §10.3, M13).

This format targets human eyeballs on GitHub / GitLab — issue comments, PR
descriptions, status checks. We keep the layout flat: header, summary
table, per-ASI section, and the top-five findings as collapsible details.

GitHub renders ``<details>`` blocks but trims them when too long; we keep
the top five so the comment stays compact.
"""

from __future__ import annotations

from pathlib import Path

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
    return (
        f"**AIVSS** `{scan.aivss}/100` "
        f"&nbsp;|&nbsp; **Band** `{band}` "
        f"({colour}) "
        f"&nbsp;|&nbsp; **Tier** `{scan.tier.value}`"
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


def _asi_section(scan: Scan) -> str:
    grouped: dict[AsiCategory, list[Finding]] = {cat: [] for cat in AsiCategory}
    for finding in scan.findings:
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


def _top_findings_section(scan: Scan, top_n: int) -> str:
    ranked = sorted(scan.findings, key=_rank)[:top_n]
    if not ranked:
        return "## Top findings\n\n_No findings — this scan came back clean._\n"
    body: list[str] = [f"## Top {len(ranked)} findings\n"]
    for finding in ranked:
        body.append(
            f"<details>\n"
            f"<summary>{_SEVERITY_BADGE[finding.severity]} "
            f"<code>{finding.probe_id}</code> — {finding.summary}</summary>\n\n"
            f"- **ASI:** `{finding.asi.value}` "
            f"({asi_description(finding.asi)})\n"
            f"- **CSA:** `{finding.csa_category.value}`\n"
            f"- **MITRE ATLAS:** "
            f"{', '.join(f'`{t}`' for t in finding.mitre_atlas)}\n"
            f"- **Confidence:** {finding.confidence:.2f} "
            f"&nbsp;|&nbsp; **Attempts:** {finding.attempt_count} "
            f"&nbsp;|&nbsp; **Success:** {finding.success}\n"
            f"- **Finding ID:** `{finding.id}`\n"
            f"</details>\n"
        )
    return "\n".join(body) + "\n"


def emit_markdown(scan: Scan, *, top_n: int = TOP_FINDINGS_DEFAULT) -> str:
    """Render a Markdown report string for ``scan``."""
    parts = [
        f"# AgentGuardian scan `{scan.id}`\n",
        f"{_badge_line(scan)}\n",
        f"- **Target:** `{scan.target_ref}` ({scan.target_mode})\n",
        f"- **Duration:** {scan.duration_seconds:.2f}s "
        f"&nbsp;|&nbsp; **Cost:** ${scan.cost_usd:.4f}\n",
        f"- **Probe library:** `{scan.probe_library_version}` "
        f"&nbsp;|&nbsp; **AIVSS formula:** `{scan.aivss_formula_version}`\n",
        f"- **Generated:** `{scan.created_at.isoformat()}`\n",
        "\n## Severity summary\n\n",
        _summary_table(scan),
        "\n",
        _asi_section(scan),
        "\n",
        _top_findings_section(scan, top_n),
    ]
    return "".join(parts)


def write_markdown(scan: Scan, path: Path, *, top_n: int = TOP_FINDINGS_DEFAULT) -> None:
    """Write the Markdown report for ``scan`` to ``path`` (UTF-8)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(emit_markdown(scan, top_n=top_n), encoding="utf-8")
