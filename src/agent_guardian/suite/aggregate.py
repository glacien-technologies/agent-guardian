"""Cross-scan aggregation — read each finished scan's report.json into a trust-
aware summary row, list every scan log folder, and write summary.json.

Pure functions here (no I/O beyond the explicit read/write helpers) so the
summary logic is unit-testable without running a scan.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

# A refusal rate at/above this means the attacker fell back to seeds too often
# for the score to be treated as an adaptive-attack result (matches the FULL
# mode refusal gate). Mirrors the scan's own authority signal.
_REFUSAL_AUTHORITY_CEILING = 0.30
_WEAK_COVERAGE_GRADES = frozenset({"D", "F"})


def report_authority(report: dict[str, Any]) -> tuple[bool, list[str]]:
    """Is this scan's score trustworthy to rank? Returns (ok, reasons-if-not)."""
    reasons: list[str] = []
    if report.get("evaluation_mode") != "real":
        reasons.append(f"evaluation_mode={report.get('evaluation_mode')!r} (not 'real')")
    if not report.get("scoring_valid", False):
        reasons.append("scoring_valid=False")
    if not report.get("mode_authoritative", False):
        reasons.append("mode_authoritative=False")
    grade = report.get("coverage_grade")
    if grade in _WEAK_COVERAGE_GRADES:
        reasons.append(f"coverage_grade={grade}")
    refusal = float((report.get("coverage") or {}).get("attacker_refusal_rate", 0.0) or 0.0)
    if refusal >= _REFUSAL_AUTHORITY_CEILING:
        reasons.append(f"attacker_refusal_rate={refusal:.0%}")
    if report.get("undertested"):
        reasons.append(f"undertested={list(report.get('undertested') or [])}")
    return (not reasons, reasons)


def read_report(scan_dir: str | Path) -> dict[str, Any] | None:
    """Load a scan's rendered report.json (the summary source of truth)."""
    path = Path(scan_dir) / "report.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        _LOG.warning("suite: could not read %s (%s) — workload row will lack a report", path, exc)
        return None
    return data if isinstance(data, dict) else None


def summary_row(
    *,
    name: str,
    scan_id: str | None,
    scan_dir: str | None,
    report: dict[str, Any] | None,
    status: str,
    exit_code: int | None,
    reports: dict[str, str],
    console_log: str | None,
) -> dict[str, Any]:
    """Build one machine-readable summary row for a finished/failed workload."""
    if report is not None:
        authoritative, reasons = report_authority(report)
        return {
            "name": name,
            "status": status,
            "exit_code": exit_code,
            "scan_id": scan_id or report.get("scan_id"),
            "log_folder": scan_dir,
            "aivss": report.get("aivss"),
            "band": report.get("band"),
            "tier": report.get("tier"),
            # #134 — confirmed findings only, so the FINDINGS column always
            # reconciles with findings_by_severity below (both derive from
            # the confirmed-only findings_summary). The unconfirmed remainder
            # travels separately.
            "findings_total": sum(dict(report.get("findings_summary") or {}).values()),
            "findings_informational": int(report.get("findings_informational") or 0),
            "findings_by_severity": dict(report.get("findings_summary") or {}),
            "refusal_rate": float(
                (report.get("coverage") or {}).get("attacker_refusal_rate", 0.0) or 0.0
            ),
            "authoritative": authoritative,
            "authority_caveats": reasons,
            "reports": reports,
            "console_log": console_log,
        }
    return {
        "name": name,
        "status": status,
        "exit_code": exit_code,
        "scan_id": scan_id,
        "log_folder": scan_dir,
        "aivss": None,
        "band": None,
        "tier": None,
        "findings_total": None,
        "findings_by_severity": {},
        "refusal_rate": None,
        "authoritative": False,
        "authority_caveats": ["no report produced"],
        "reports": reports,
        "console_log": console_log,
    }


def write_summary_json(rows: list[dict[str, Any]], path: str | Path) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"workloads": rows}, indent=2), encoding="utf-8")


def format_summary_lines(rows: list[dict[str, Any]]) -> list[str]:
    """Plain-text summary table + totals + the explicit scan-log-folder list."""
    lines: list[str] = []
    lines.append("SUMMARY")
    header = (
        f"{'WORKLOAD':<22}{'STATUS':<9}{'AIVSS':>6}  {'BAND':<15}{'TIER':<5}{'FINDINGS':>9}  TRUST"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for r in rows:
        aivss = "-" if r["aivss"] is None else str(r["aivss"])
        band = r["band"] or "-"
        tier = r["tier"] or "-"
        findings = "-" if r["findings_total"] is None else str(r["findings_total"])
        trust = "authoritative" if r["authoritative"] else "CAVEAT"
        lines.append(
            f"{r['name']:<22}{r['status']:<9}{aivss:>6}  {band:<15}{tier:<5}{findings:>9}  {trust}"
        )

    ok_rows = [r for r in rows if r["status"] == "ok" and r["aivss"] is not None]
    failed = [r for r in rows if r["status"] != "ok"]
    lines.append("")
    lines.append(f"TOTALS: {len(rows)} workloads — {len(ok_rows)} completed, {len(failed)} failed")
    if ok_rows:
        worst = min(ok_rows, key=lambda r: r["aivss"])
        lines.append(f"  weakest target: {worst['name']} (AIVSS {worst['aivss']} {worst['band']})")

    lines.append("")
    lines.append("Scan log folders:")
    for r in rows:
        folder = r["log_folder"] or "(none — scan did not complete)"
        lines.append(f"  {r['name']}: {folder}")
    return lines
