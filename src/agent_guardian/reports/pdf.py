"""PDF report emitter (PRD §10.2, M13).

WeasyPrint is the primary engine (full-fidelity layout, real typography).
It depends on native libraries (``libpango``, ``libpangoft2``) that are
not present on bare CI runners — so we ship a ReportLab fallback in
:mod:`agent_guardian.reports.pdf_reportlab` that emits a single-page
summary using only stdlib + ReportLab.

Engine selection order:

1. ``engine`` kwarg, if passed.
2. ``AGENT_GUARDIAN_PDF_ENGINE`` env var (``weasyprint`` or ``reportlab``).
3. WeasyPrint if importable, otherwise ReportLab.

If neither is available, we raise :class:`PdfFeatureUnavailable` with an
install hint pointing at the right extras (``[full]`` or ``[pdf-fallback]``).
"""

from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path
from typing import Any

from agent_guardian.core.redact import redact_finding
from agent_guardian.models.asi import AsiCategory, asi_description
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import colour_for_band

_LOG = logging.getLogger(__name__)

__all__ = [
    "PDF_ENV_VAR",
    "PdfFeatureUnavailable",
    "available_pdf_engines",
    "render_report_html",
    "write_pdf",
]

PDF_ENV_VAR = "AGENT_GUARDIAN_PDF_ENGINE"


class PdfFeatureUnavailable(RuntimeError):
    """Raised when no PDF engine is importable.

    Install ``agent-guardian[full]`` for WeasyPrint (rich layout) or
    ``agent-guardian[pdf-fallback]`` for the smaller ReportLab fallback.
    """


def _has_weasyprint() -> bool:
    """Return ``True`` only when WeasyPrint can render to PDF end-to-end.

    The python wheel imports without its native dependencies (``cairo`` /
    ``pango`` / ``libgobject``), so a plain ``importlib.util.find_spec`` check
    would lie: ``write_pdf`` would later die with an unhelpful CFFI
    ``OSError: cannot load library 'libgobject-2.0-0'`` on a stock macOS or
    minimal-Linux box that has the python wheel but not the system libs. We
    instead probe a minimal render once and cache the result so operators get
    a clear ``PdfFeatureUnavailable`` (with install hint) up front and we
    transparently fall back to ReportLab when only the wheel is present.
    """
    if importlib.util.find_spec("weasyprint") is None:
        return False
    cached: bool | None = getattr(_has_weasyprint, "_native_ok", None)
    if cached is not None:
        return cached
    try:
        import weasyprint  # type: ignore[import-not-found,import-untyped,unused-ignore]

        weasyprint.HTML(string="<p>probe</p>").write_pdf()
        ok = True
    except Exception as exc:
        _LOG.debug(
            "pdf: WeasyPrint imported but native deps unavailable (%s: %s); "
            "treating as unavailable and falling through to ReportLab.",
            type(exc).__name__,
            exc,
        )
        ok = False
    _has_weasyprint._native_ok = ok  # type: ignore[attr-defined]
    return ok


def _has_reportlab() -> bool:
    return importlib.util.find_spec("reportlab") is not None


def available_pdf_engines() -> tuple[str, ...]:
    """Return the importable engines, in preference order."""
    engines: list[str] = []
    if _has_weasyprint():
        engines.append("weasyprint")
    if _has_reportlab():
        engines.append("reportlab")
    return tuple(engines)


def _resolve_engine(engine: str | None) -> str:
    candidate = engine or os.environ.get(PDF_ENV_VAR)
    if candidate:
        candidate = candidate.lower()
        if candidate not in {"weasyprint", "reportlab"}:
            raise ValueError(
                f"Unknown PDF engine '{candidate}' — expected 'weasyprint' or 'reportlab'."
            )
        if candidate == "weasyprint" and not _has_weasyprint():
            if _has_reportlab():
                return "reportlab"
            raise PdfFeatureUnavailable(
                "WeasyPrint requested but not importable. Install "
                "'agent-guardian[full]' (and its native deps libpango / "
                "libpangoft2), or fall back with "
                "AGENT_GUARDIAN_PDF_ENGINE=reportlab "
                "+ 'agent-guardian[pdf-fallback]'."
            )
        if candidate == "reportlab" and not _has_reportlab():
            raise PdfFeatureUnavailable(
                "ReportLab requested but not importable. Install 'agent-guardian[pdf-fallback]'."
            )
        return candidate
    # Auto-select.
    if _has_weasyprint():
        return "weasyprint"
    if _has_reportlab():
        return "reportlab"
    raise PdfFeatureUnavailable(
        "No PDF engine available. Install 'agent-guardian[full]' for "
        "WeasyPrint or 'agent-guardian[pdf-fallback]' for ReportLab."
    )


def _build_asi_rows(findings: list[Finding], scan: Scan) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    by_asi: dict[AsiCategory, list[Any]] = {cat: [] for cat in AsiCategory}
    for finding in findings:
        by_asi[finding.asi].append(finding)
    for category in AsiCategory:  # codeql[py/non-iterable-in-for-loop]
        cat_findings = by_asi[category]
        rows.append(
            {
                "id": category.value,
                "description": asi_description(category),
                "score": scan.asi_scores.get(category, 100.0),
                "count": len(cat_findings),
                "findings": cat_findings,
            }
        )
    return rows


def render_report_html(scan: Scan, *, redact: bool = True) -> str:
    """Render the enterprise PDF report template to an HTML string.

    Engine-independent (no WeasyPrint): redacts PII/credential shapes from the
    findings, then renders ``pdf/report.html.jinja`` with the locked template
    vars (``scan`` / ``findings`` / ``asi_rows`` / ``band_colour``). The PDF
    engines wrap this; exposing it directly makes the template content testable
    without the native WeasyPrint stack.
    """
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    # Scrub PII + credential shapes from finding text before it reaches the
    # template (Jinja autoescape handles HTML escaping; redaction handles
    # secrets/PII). The template renders the ``findings`` var, not scan.findings.
    findings = [redact_finding(f, enabled=redact) for f in scan.findings]
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "jinja"]),
    )
    template = env.get_template("pdf/report.html.jinja")
    return template.render(
        scan=scan,
        findings=findings,
        asi_rows=_build_asi_rows(findings, scan),
        band_colour=colour_for_band(scan.band),
    )


def _render_weasyprint(
    scan: Scan, path: Path, *, redact: bool
) -> None:  # pragma: no cover — needs native libs
    from weasyprint import HTML  # type: ignore[import-not-found,import-untyped,unused-ignore]

    html_str = render_report_html(scan, redact=redact)
    path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_str).write_pdf(str(path))


def write_pdf(scan: Scan, path: Path, *, engine: str | None = None, redact: bool = True) -> None:
    """Render ``scan`` to PDF at ``path`` using the best available engine."""
    chosen = _resolve_engine(engine)
    if chosen == "weasyprint":
        _render_weasyprint(scan, path, redact=redact)
        return
    # Fallback path — always importable on systems with reportlab installed.
    from agent_guardian.reports.pdf_reportlab import write_pdf_reportlab

    write_pdf_reportlab(scan, path, redact=redact)
