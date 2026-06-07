"""ReportLab PDF fallback (PRD §10.2, M13).

WeasyPrint is the preferred engine because of its rich CSS layout, but it
requires native ``libpango`` libraries that aren't on CI runners. ReportLab
is pure Python, so it's a small fallback that fits in the
``[pdf-fallback]`` extra. The output is intentionally simple: a single
letter-sized page summarising the scan.
"""

from __future__ import annotations

from pathlib import Path

from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.scan import Scan

__all__ = ["write_pdf_reportlab"]


def write_pdf_reportlab(
    scan: Scan, path: Path, *, redact: bool = True
) -> None:  # pragma: no cover — needs reportlab
    """Render a single-page summary PDF using ReportLab.

    The output is intentionally minimal — the canonical artefact is the
    JSON report; this PDF exists so CI without native libs can still
    produce *something* humans can open. It emits only aggregate stats (AIVSS,
    severity counts, per-ASI scores) and no per-finding text, so ``redact`` is
    accepted for signature parity with :func:`agent_guardian.reports.pdf.write_pdf`
    but there is no finding text to scrub here.

    When ``scan.scoring_valid`` is False (a stub / non-authoritative run) the
    numeric AIVSS is suppressed and a "NOT EVALUATED — non-authoritative run;
    AIVSS suppressed." notice is rendered instead — mirroring the WeasyPrint
    template so the two engines stay in lockstep and a vacuous stub run cannot
    masquerade as a passing scan in the fallback path.
    """
    _ = redact  # no finding text rendered in the fallback; nothing to scrub
    # ReportLab ships no type stubs; mypy reports either `import-untyped`
    # (when reportlab is installed) or `import-not-found` (when it isn't),
    # so we silence both error codes plus the `unused-ignore` that would
    # fire when only one triggers. Module-level imports keep the type-ignore
    # comment co-located with the import statement that ruff format leaves
    # alone.
    import reportlab.lib.pagesizes as _pagesizes  # type: ignore[import-untyped,import-not-found,unused-ignore]
    import reportlab.pdfgen.canvas as _canvas  # type: ignore[import-untyped,import-not-found,unused-ignore]

    path.parent.mkdir(parents=True, exist_ok=True)
    _width, height = _pagesizes.letter
    c = _canvas.Canvas(str(path), pagesize=_pagesizes.letter)

    # Header
    c.setFont("Helvetica-Bold", 22)
    c.drawString(72, height - 72, "AgentGuardian Scan Report")
    c.setFont("Helvetica", 11)
    c.setFillGray(0.35)
    c.drawString(72, height - 92, f"Scan ID: {scan.id}")
    c.setFillGray(0.0)

    # Top stats — suppress the AIVSS number on stub / non-authoritative runs.
    # Otherwise the PDF would print "AIVSS: 70 / 100 (not_evaluated)" which is
    # a misleading mash-up: ``not_evaluated`` means there is no trustworthy
    # number, yet the 70 is sat right next to it. Mirror the WeasyPrint
    # template (templates/pdf/report.html.jinja) verbatim.
    c.setFont("Helvetica-Bold", 16)
    aivss_label = f"{scan.aivss} / 100" if scan.scoring_valid else "n/a (not evaluated)"
    c.drawString(72, height - 130, f"AIVSS: {aivss_label}   ({scan.band.value})")
    notice_offset = 0
    if not scan.scoring_valid:
        c.setFont("Helvetica-Oblique", 10)
        c.setFillGray(0.35)
        c.drawString(
            72,
            height - 146,
            "NOT EVALUATED - non-authoritative run; AIVSS suppressed.",
        )
        c.setFillGray(0.0)
        notice_offset = 16
    c.setFont("Helvetica", 11)
    c.drawString(72, height - 152 - notice_offset, f"Tier: {scan.tier.value}")
    c.drawString(
        72,
        height - 168 - notice_offset,
        f"Target: {scan.target_ref} ({scan.target_mode})",
    )
    c.drawString(
        72,
        height - 184 - notice_offset,
        f"Duration: {scan.duration_seconds:.2f}s   Cost: ${scan.cost_usd:.4f}",
    )
    c.drawString(72, height - 200 - notice_offset, f"Generated: {scan.created_at.isoformat()}")
    c.drawString(
        72,
        height - 216 - notice_offset,
        f"Probe library: {scan.probe_library_version}   AIVSS formula: {scan.aivss_formula_version}",
    )

    # Severity summary
    summary = scan.findings_summary()
    c.setFont("Helvetica-Bold", 13)
    c.drawString(72, height - 252 - notice_offset, "Severity summary")
    c.setFont("Helvetica", 11)
    rows = [
        ("Critical", summary["critical"]),
        ("High", summary["high"]),
        ("Medium", summary["medium"]),
        ("Low", summary["low"]),
        ("Total", sum(summary.values())),
    ]
    y = height - 272 - notice_offset
    for label, count in rows:
        c.drawString(90, y, f"{label:<10}{count}")
        y -= 15

    # ASI breakdown
    c.setFont("Helvetica-Bold", 13)
    c.drawString(72, y - 10, "ASI breakdown")
    c.setFont("Helvetica", 10)
    y -= 28
    for category in AsiCategory:  # codeql[py/non-iterable-in-for-loop]
        score = scan.asi_scores.get(category, 100.0)
        finding_count = sum(1 for f in scan.findings if f.asi == category)
        c.drawString(
            90,
            y,
            f"{category.value}  {asi_description(category):<28}  "
            f"score={score:5.1f}  findings={finding_count}",
        )
        y -= 14

    # Footer
    c.setFont("Helvetica-Oblique", 9)
    c.setFillGray(0.4)
    c.drawString(
        72,
        50,
        "Generated by AgentGuardian — canonical artefact is the signed JSON report.",
    )

    c.showPage()
    c.save()
