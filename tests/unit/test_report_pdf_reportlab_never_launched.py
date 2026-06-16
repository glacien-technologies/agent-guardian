"""ReportLab PDF fallback — issue #230 ``never_launched`` rendering.

The WeasyPrint template (``templates/pdf/report.html.jinja``) renders
``scan.never_launched`` ASI rows as ``N/A`` instead of the ``0.0``
sentinel — mirroring the markdown / SARIF / JSON emitters. The
ReportLab fallback (used by the ``[pdf-fallback]`` extra and exercised
by the rc37 release matrix) used to unconditionally print
``score= 0.0  findings=0`` for the same rows, which reads to a CI
consumer as "we tested ASI07 and the agent failed flat" — the exact
inverse of the truth ("recon never launched the lane").

These tests pin the cross-emitter contract from PR #210 / #241 for the
ReportLab path.
"""

from __future__ import annotations

import importlib.util
from io import StringIO
from pathlib import Path

import pytest

from tests.unit._report_fixtures import make_scan

HAS_REPORTLAB = importlib.util.find_spec("reportlab") is not None
HAS_PDFMINER = importlib.util.find_spec("pdfminer") is not None

pytestmark = pytest.mark.skipif(
    not (HAS_REPORTLAB and HAS_PDFMINER),
    reason="reportlab + pdfminer.six required (install dev extra)",
)


def _extract_text(path: Path) -> str:
    from pdfminer.high_level import extract_text_to_fp
    from pdfminer.layout import LAParams

    buf = StringIO()
    with path.open("rb") as fh:
        extract_text_to_fp(fh, buf, laparams=LAParams())
    return buf.getvalue()


def _asi_line(text: str, asi: str) -> str:
    """Return the single rendered line that begins with the given ASI id.

    pdfminer can wrap or split rows; locate the matching line by prefix
    rather than scanning the whole document so the assertions cannot
    pick up a stray substring from elsewhere on the page.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(asi + " ") or line.startswith(asi + "\t"):
            return line
    raise AssertionError(f"no rendered row for {asi}; full text was:\n{text}")


def test_reportlab_never_launched_renders_na_not_zero(tmp_path: Path) -> None:
    """Issue #230 — a category in ``scan.never_launched`` renders as ``N/A``
    in the ASI breakdown, never the ``score=0.0 findings=0`` sentinel.

    Without the fix the ReportLab fallback drew
    ``score=  0.0  findings=0`` for never-launched lanes, masquerading a
    never-tested category as a confirmed-zero result.
    """
    from agent_guardian.reports.pdf_reportlab import write_pdf_reportlab

    base = make_scan()
    # Pin ASI07 to the sentinel that exposed the bug in the rc37 matrix:
    # asi_scores recorded 0.0 because the lane never launched, but the
    # absence of any finding made it look like a clean pass.
    scores = dict(base.asi_scores)
    from agent_guardian.models.asi import AsiCategory

    scores[AsiCategory.ASI07] = 0.0
    scan = base.model_copy(
        update={
            "asi_scores": scores,
            "never_launched": ["ASI07"],
        }
    )

    out = tmp_path / "report.pdf"
    write_pdf_reportlab(scan, out)
    text = _extract_text(out)

    asi07_line = _asi_line(text, "ASI07")
    assert "N/A" in asi07_line, (
        "ReportLab rendered ASI07 without the N/A marker even though the "
        f"scan declared never_launched=['ASI07']; row was {asi07_line!r}"
    )
    assert "0.0" not in asi07_line, (
        "ReportLab rendered ASI07 with the 0.0 sentinel for a never-launched "
        f"category — exactly the rc37 deep-review HIGH-2 bug; row was {asi07_line!r}"
    )
    assert "findings=0" not in asi07_line, (
        "ReportLab rendered ASI07 with findings=0 for a never-launched "
        f"category; the row should suppress the count too. Row was {asi07_line!r}"
    )


def test_reportlab_launched_categories_still_render_scores(tmp_path: Path) -> None:
    """Categories NOT in ``never_launched`` keep the numeric ``score=`` /
    ``findings=`` rendering — the fix targets only the never-launched rows."""
    from agent_guardian.reports.pdf_reportlab import write_pdf_reportlab

    base = make_scan()
    scan = base.model_copy(update={"never_launched": ["ASI07"]})

    out = tmp_path / "report.pdf"
    write_pdf_reportlab(scan, out)
    text = _extract_text(out)

    # ASI01 is launched (and has a CRITICAL finding from the fixture). The
    # numeric score must still appear.
    asi01_line = _asi_line(text, "ASI01")
    assert "score=" in asi01_line
    assert "findings=" in asi01_line
    assert "N/A" not in asi01_line
