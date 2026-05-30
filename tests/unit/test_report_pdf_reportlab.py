"""ReportLab PDF fallback tests (P1 — stub-run AIVSS suppression).

The ReportLab fallback used to render the literal ``AIVSS: 70 / 100
(not_evaluated)`` for any stub / non-authoritative run that the scoring
phase had marked ``scoring_valid=False``. That mashes a vacuous number
right next to the ``not_evaluated`` band label — a reader could believe
the 70 was a real score. The WeasyPrint template already suppresses the
number; the fallback now matches.

These tests skip cleanly when reportlab + pdfminer.six are not both
installed; the dev extra ships both so CI exercises the path.
"""

from __future__ import annotations

import importlib.util
from io import StringIO
from pathlib import Path

import pytest

from agent_guardian.models.severity import SeverityBand
from tests.unit._report_fixtures import make_scan

HAS_REPORTLAB = importlib.util.find_spec("reportlab") is not None
HAS_PDFMINER = importlib.util.find_spec("pdfminer") is not None

pytestmark = pytest.mark.skipif(
    not (HAS_REPORTLAB and HAS_PDFMINER),
    reason="reportlab + pdfminer.six required (install dev extra)",
)


def _extract_text(path: Path) -> str:
    """Pull text out of a one-page ReportLab PDF via pdfminer.six."""
    from pdfminer.high_level import extract_text_to_fp
    from pdfminer.layout import LAParams

    buf = StringIO()
    with path.open("rb") as fh:
        extract_text_to_fp(fh, buf, laparams=LAParams())
    return buf.getvalue()


def test_reportlab_renders_aivss_when_scoring_valid(tmp_path: Path) -> None:
    """A real run (``scoring_valid=True``, default) prints the numeric AIVSS."""
    from agent_guardian.reports.pdf_reportlab import write_pdf_reportlab

    scan = make_scan(aivss=72)
    out = tmp_path / "report.pdf"
    write_pdf_reportlab(scan, out)
    text = _extract_text(out)
    assert "AIVSS:" in text
    assert "72" in text
    # The "NOT EVALUATED" notice belongs only to stub runs.
    assert "NOT EVALUATED" not in text


def test_reportlab_suppresses_aivss_when_scoring_invalid(tmp_path: Path) -> None:
    """P1 regression: stub-style run with ``scoring_valid=False`` and
    ``band=NOT_EVALUATED`` must NOT print the numeric AIVSS and MUST print a
    "NOT EVALUATED" notice. The misleading 'AIVSS: 70 / 100 (not_evaluated)'
    mash-up is the exact bug this guards against."""
    from agent_guardian.reports.pdf_reportlab import write_pdf_reportlab

    base = make_scan(aivss=70)
    # Override the band + scoring_valid to model a stub run. The Scan model is
    # immutable Pydantic; use model_copy.
    scan = base.model_copy(
        update={
            "aivss": 70,
            "scoring_valid": False,
            "band": SeverityBand.NOT_EVALUATED,
        }
    )
    out = tmp_path / "report.pdf"
    write_pdf_reportlab(scan, out)
    text = _extract_text(out)
    # The misleading "AIVSS: 70" header must not appear.
    assert "AIVSS: 70" not in text, (
        "ReportLab fallback rendered the suppressed numeric AIVSS on a "
        "non-authoritative run — exactly the bug the fix targets."
    )
    # The fix prints "n/a (not evaluated)" in the header slot AND a
    # standalone notice. Either signal proves the suppression fired; assert
    # the loud one.
    assert "NOT EVALUATED" in text or "n/a" in text


def test_reportlab_band_label_still_present_on_stub_run(tmp_path: Path) -> None:
    """Even with the AIVSS number suppressed, the band label is still rendered
    so the reader can tell which non-authoritative state they're in."""
    from agent_guardian.reports.pdf_reportlab import write_pdf_reportlab

    base = make_scan(aivss=70)
    scan = base.model_copy(
        update={
            "scoring_valid": False,
            "band": SeverityBand.NOT_EVALUATED,
        }
    )
    out = tmp_path / "report.pdf"
    write_pdf_reportlab(scan, out)
    text = _extract_text(out)
    assert SeverityBand.NOT_EVALUATED.value in text  # "not_evaluated"
