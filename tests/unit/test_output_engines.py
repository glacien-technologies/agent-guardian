"""Per-format engine-probe coverage for :mod:`agent_guardian.reports.output_engines`.

The probe is the single source of truth for two distinct CLI closures
(QA-010 fail-fast at scan-start, QA-011 plan-panel OUTPUTS row), so the
behaviour matrix is locked test-by-test here. Coverage target: ≥90% on
``output_engines.py`` — the cases below exercise every branch.
"""

from __future__ import annotations

import pytest

from agent_guardian.reports.output_engines import (
    ALL_FORMATS,
    EngineCheck,
    validate_output_engine_available,
)

# ---------- always-on text formats ----------


@pytest.mark.parametrize("fmt", ["json", "sarif", "junit", "md"])
def test_text_formats_always_ok(fmt: str) -> None:
    """json/sarif/junit/md all resolve to the stdlib engine without any extras."""
    check = validate_output_engine_available(fmt)
    assert check.status == "ok"
    assert check.engine == "stdlib"
    assert check.available is True
    assert check.install_hint == ""
    assert check.missing_extra == ""
    assert check.message == ""


# ---------- pdf branches ----------


def test_pdf_ok_when_weasyprint_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """WeasyPrint is the preferred engine when its native deps are live."""
    monkeypatch.setattr("agent_guardian.reports.pdf._has_weasyprint", lambda: True)
    monkeypatch.setattr("agent_guardian.reports.pdf._has_reportlab", lambda: True)
    check = validate_output_engine_available("pdf")
    assert check.status == "ok"
    assert check.engine == "weasyprint"
    assert check.available is True


def test_pdf_falls_back_to_reportlab(monkeypatch: pytest.MonkeyPatch) -> None:
    """WeasyPrint absent → ReportLab takes over; QA-010 guarantees ReportLab is in base."""
    monkeypatch.setattr("agent_guardian.reports.pdf._has_weasyprint", lambda: False)
    monkeypatch.setattr("agent_guardian.reports.pdf._has_reportlab", lambda: True)
    check = validate_output_engine_available("pdf")
    assert check.status == "ok"
    assert check.engine == "reportlab"
    assert check.available is True


def test_pdf_missing_when_both_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """No PDF engine importable at all → missing + install hint."""
    monkeypatch.setattr("agent_guardian.reports.pdf._has_weasyprint", lambda: False)
    monkeypatch.setattr("agent_guardian.reports.pdf._has_reportlab", lambda: False)
    check = validate_output_engine_available("pdf")
    assert check.status == "missing"
    assert check.available is False
    assert check.engine == ""
    assert "PDF engine" in check.message
    assert check.install_hint == "pip install agent-guardian[full]"
    assert check.missing_extra == "pip install agent-guardian[full]"


# ---------- unknown formats ----------


def test_unknown_format_returns_unknown_status() -> None:
    """An unknown format string falls into the discrete unknown_format bucket."""
    check = validate_output_engine_available("xlsx")
    assert check.status == "unknown_format"
    assert check.available is False
    assert "xlsx" in check.message
    # Listed alternatives include every advertised format.
    for fmt in ALL_FORMATS:
        assert fmt in check.message
    # No install hint — the format isn't ours to install a writer for.
    assert check.install_hint == ""


def test_unknown_format_preserves_original_format_in_message() -> None:
    """The raw operator input should appear in the message verbatim."""
    check = validate_output_engine_available("docx")
    assert "'docx'" in check.message


# ---------- normalisation ----------


@pytest.mark.parametrize("variant", ["PDF", "Pdf", "pDf"])
def test_case_insensitive_format(variant: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Mixed-case format strings normalise to lower; outcome is identical."""
    monkeypatch.setattr("agent_guardian.reports.pdf._has_weasyprint", lambda: False)
    monkeypatch.setattr("agent_guardian.reports.pdf._has_reportlab", lambda: True)
    check = validate_output_engine_available(variant)
    assert check.format == "pdf"
    assert check.status == "ok"
    assert check.engine == "reportlab"


@pytest.mark.parametrize("variant", ["JSON", "Json"])
def test_case_insensitive_text_format(variant: str) -> None:
    check = validate_output_engine_available(variant)
    assert check.format == "json"
    assert check.status == "ok"
    assert check.engine == "stdlib"


# ---------- dataclass surface ----------


def test_engine_check_is_frozen() -> None:
    """EngineCheck is immutable; consumers cannot mutate the probe result."""
    check = validate_output_engine_available("json")
    with pytest.raises((AttributeError, TypeError)):
        check.status = "missing"  # type: ignore[misc]


def test_engine_check_all_formats_enumerable() -> None:
    """Every advertised format produces a non-error EngineCheck."""
    for fmt in ALL_FORMATS:
        check = validate_output_engine_available(fmt)
        assert isinstance(check, EngineCheck)
        # For pdf we don't know the env; but status is never unknown_format
        # for an advertised format.
        assert check.status in {"ok", "missing"}
