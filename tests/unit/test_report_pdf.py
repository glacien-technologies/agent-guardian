"""PDF report emitter tests (M13).

The PDF engines (WeasyPrint, ReportLab) live in optional extras
(``[full]`` and ``[pdf-fallback]``). On a bare CI runner neither is
installed — these tests skip cleanly. When a developer has one engine
installed locally we exercise the matching code path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from agent_guardian.reports.pdf import (
    PDF_ENV_VAR,
    PdfFeatureUnavailable,
    available_pdf_engines,
    write_pdf,
)
from tests.unit._report_fixtures import make_scan


def _weasyprint_runtime_available() -> bool:
    """Mirror ``agent_guardian.reports.pdf._has_weasyprint`` — render-time probe.

    The python wheel imports without its native deps (``cairo`` / ``pango`` /
    ``libgobject``); a stock macOS box without Homebrew has the wheel but
    cannot render. Skip rather than fail with a dlopen ``OSError``.
    """
    if importlib.util.find_spec("weasyprint") is None:
        return False
    try:
        import weasyprint  # type: ignore[import-untyped,unused-ignore]

        weasyprint.HTML(string="<p>probe</p>").write_pdf()
    except Exception:
        return False
    return True


HAS_WEASYPRINT = _weasyprint_runtime_available()
HAS_REPORTLAB = importlib.util.find_spec("reportlab") is not None


def test_available_engines_returns_subset_of_known() -> None:
    engines = set(available_pdf_engines())
    assert engines.issubset({"weasyprint", "reportlab"})


def test_write_pdf_raises_when_no_engine_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if HAS_WEASYPRINT or HAS_REPORTLAB:
        pytest.skip("a PDF engine is installed; cannot exercise unavailable path")
    monkeypatch.delenv(PDF_ENV_VAR, raising=False)
    with pytest.raises(PdfFeatureUnavailable):
        write_pdf(make_scan(), tmp_path / "report.pdf")


def test_write_pdf_explicit_weasyprint_falls_back_to_reportlab(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if HAS_WEASYPRINT or not HAS_REPORTLAB:
        pytest.skip("needs reportlab-only environment to exercise fallback path")
    monkeypatch.setenv(PDF_ENV_VAR, "weasyprint")
    out = tmp_path / "report.pdf"
    write_pdf(make_scan(), out)
    assert out.is_file()


@pytest.mark.skipif(not HAS_REPORTLAB, reason="reportlab not installed")
def test_write_pdf_reportlab_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(PDF_ENV_VAR, "reportlab")
    out = tmp_path / "report.pdf"
    write_pdf(make_scan(), out)
    assert out.is_file()
    # Minimum sanity — PDF header bytes.
    assert out.read_bytes().startswith(b"%PDF")


@pytest.mark.skipif(not HAS_WEASYPRINT, reason="weasyprint not installed")
def test_write_pdf_weasyprint_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(PDF_ENV_VAR, "weasyprint")
    out = tmp_path / "report.pdf"
    write_pdf(make_scan(), out)
    assert out.is_file()
    assert out.read_bytes().startswith(b"%PDF")


def test_write_pdf_rejects_unknown_engine(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        write_pdf(make_scan(), tmp_path / "report.pdf", engine="parchment")


# ---------------------------------------------------------------------------
# Enterprise template render (engine-independent — no WeasyPrint needed)
# ---------------------------------------------------------------------------


def test_report_template_renders_enterprise_sections() -> None:
    """The redesigned PDF template renders Overview + Findings, themed.

    Exercises ``render_report_html`` directly (the Jinja half of the WeasyPrint
    path) so the enterprise template has coverage on a bare runner.
    """
    from agent_guardian.models.asi import AsiCategory
    from agent_guardian.reports.pdf import render_report_html

    # asi_scores: ASI01=40 (warm), ASI02=60 (warm); add a <40 to exercise 'hot'.
    scan = make_scan(
        aivss=43,
        asi_scores={cat: 90.0 for cat in AsiCategory}
        | {
            AsiCategory.ASI01: 30.0,  # < 40 -> hot
            AsiCategory.ASI02: 60.0,  # < 70 -> warm
        },
    )
    html = render_report_html(scan, redact=True)

    # Cover + the three content sections an enterprise report must carry.
    assert "Agentic Threat Posture Report" in html
    assert str(scan.aivss) in html
    assert scan.band.value in html
    for heading in ("Executive Summary", "Overview", "Findings"):
        assert heading in html, f"missing section: {heading}"
    # Overview must surface the scan plan (target + models).
    assert scan.target_ref in html
    # Dashboard theme: brand purple + severity coding present in the stylesheet.
    assert "#8b5cf6" in html
    # Resilience score wording is correct (higher = stronger, not "greater exposure").
    assert "greater exposure" not in html
    assert "higher = stronger" in html
    # Score-bar severity classes fire for low resilience.
    assert "scorebar hot" in html
    assert "scorebar warm" in html


def test_report_template_handles_zero_findings() -> None:
    """A clean scan renders without error and shows no findings gracefully."""
    from agent_guardian.reports.pdf import render_report_html

    scan = make_scan(aivss=100, findings=[])
    html = render_report_html(scan, redact=True)
    assert "Agentic Threat Posture Report" in html
    assert "100" in html
