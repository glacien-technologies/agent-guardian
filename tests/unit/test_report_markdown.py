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


# --- finding #21: HTML-escape finding text so <script> can't inject -----


def test_emit_markdown_escapes_script_in_summary() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    nasty = make_finding(
        id="f_xss",
        probe_id="ASI01-GH-XSS",
        severity=Severity.CRITICAL,
        summary='<script>alert("pwn")</script> reflected',
    )
    md = emit_markdown(make_scan(findings=[nasty]))
    # The raw <script> tag must NOT appear; it must be HTML-escaped.
    assert "<script>" not in md
    assert "&lt;script&gt;" in md


def test_emit_markdown_escapes_probe_id_and_finding_id() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    nasty = make_finding(
        id="f<id>",
        probe_id="ASI01<img src=x>",
        severity=Severity.HIGH,
        summary="ok",
    )
    md = emit_markdown(make_scan(findings=[nasty]))
    assert "<img src=x>" not in md
    assert "&lt;img src=x&gt;" in md


# --- finding #2: secret redaction in markdown ---------------------------


def test_emit_markdown_redacts_secrets() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    leaky = make_finding(
        id="f_leak",
        probe_id="ASI02-TM-009",
        severity=Severity.HIGH,
        summary="leaked AKIAIOSFODNN7EXAMPLE in response",
    )
    md = emit_markdown(make_scan(findings=[leaky]))
    assert "AKIAIOSFODNN7EXAMPLE" not in md
    assert "[REDACTED:AWS_ACCESS_KEY]" in md


def test_emit_markdown_redact_false_leaves_raw() -> None:
    from agent_guardian.models.severity import Severity
    from tests.unit._report_fixtures import make_finding

    leaky = make_finding(
        id="f_leak2",
        probe_id="ASI02-TM-010",
        severity=Severity.HIGH,
        summary="raw user@example.com",
    )
    md = emit_markdown(make_scan(findings=[leaky]), redact=False)
    assert "user@example.com" in md


def test_emit_markdown_mirrors_audit_section() -> None:
    scan = make_scan().model_copy(
        update={
            "audit": {
                "contract_sha256": "e" * 64,
                "suppressed_tool_attempts": 47,
                "egress_refused_turns": 6,
            }
        }
    )
    md = emit_markdown(scan)
    assert "Rules of Engagement / Audit" in md
    assert "e" * 64 in md
    assert "47" in md
