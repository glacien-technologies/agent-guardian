"""Markdown report emitter tests (M13)."""

from __future__ import annotations

from pathlib import Path

from agent_guardian.reports.markdown import emit_markdown, write_markdown
from tests.unit._report_fixtures import make_scan


def test_emit_markdown_contains_scan_id() -> None:
    scan = make_scan()
    md = emit_markdown(scan)
    assert scan.id in md


def test_emit_markdown_contains_aivss_and_band() -> None:
    scan = make_scan()
    md = emit_markdown(scan)
    assert f"`{scan.aivss}/100`" in md
    assert scan.band.value in md


def test_emit_markdown_lists_all_asi_categories() -> None:
    md = emit_markdown(make_scan())
    for asi in (
        "ASI01",
        "ASI02",
        "ASI03",
        "ASI04",
        "ASI05",
        "ASI06",
        "ASI07",
        "ASI08",
        "ASI09",
        "ASI10",
    ):
        assert asi in md


def test_emit_markdown_top_findings_section_shows_summaries() -> None:
    scan = make_scan()
    md = emit_markdown(scan)
    for f in scan.findings[:3]:
        assert f.summary in md


def test_emit_markdown_handles_empty_findings() -> None:
    scan = make_scan(findings=[])
    md = emit_markdown(scan)
    assert "No findings" in md or "clean" in md


def test_emit_markdown_respects_top_n() -> None:
    scan = make_scan()
    md = emit_markdown(scan, top_n=1)
    # Should mention "Top 1 findings".
    assert "Top 1 finding" in md


def test_write_markdown_writes_file(tmp_path: Path) -> None:
    path = tmp_path / "report.md"
    write_markdown(make_scan(), path)
    body = path.read_text(encoding="utf-8")
    assert body.startswith("# AgentGuardian scan")


def test_emit_markdown_severity_summary_table_present() -> None:
    md = emit_markdown(make_scan())
    assert "Severity summary" in md
    assert "Critical" in md
    assert "Total" in md
