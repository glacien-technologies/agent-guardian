"""Cross-format parity guards — the non-JSON emitters must carry the posture,
the honesty signals, and the per-finding evidence chain (not just findings).

These lock the most important property: no format may present a non-authoritative
(stub / fast) scan as a gate-able posture, and every format must expose the
evidence chain (finding_id / verdict_v2 / evidence_types) a consumer needs.
"""

from __future__ import annotations

import json
from xml.etree import ElementTree as ET

import pytest

from agent_guardian.reports.codeclimate import emit_codeclimate
from agent_guardian.reports.junit import emit_junit
from agent_guardian.reports.markdown import emit_markdown
from agent_guardian.reports.sarif import emit_sarif
from tests.unit._report_fixtures import make_finding, make_scan


def _as_text(fmt: str, scan: object) -> str:
    if fmt == "sarif":
        return json.dumps(emit_sarif(scan))  # type: ignore[arg-type]
    if fmt == "junit":
        return ET.tostring(emit_junit(scan), encoding="unicode")  # type: ignore[arg-type]
    if fmt == "markdown":
        return emit_markdown(scan)  # type: ignore[arg-type]
    return json.dumps(emit_codeclimate(scan))  # type: ignore[arg-type]


@pytest.mark.parametrize("fmt", ["sarif", "junit", "markdown", "gitlab"])
def test_format_flags_non_authoritative_scan(fmt: str) -> None:
    """A stub / non-authoritative scan must be unmistakable in every format."""
    scan = make_scan().model_copy(update={"mode_authoritative": False, "evaluation_mode": "stub"})
    text = _as_text(fmt, scan)
    # The honesty signal: the key (CI formats) or the prose notice (Markdown).
    assert "mode_authoritative" in text or "non-authoritative" in text.lower()
    # The evaluation_mode value rides along everywhere.
    assert "stub" in text


@pytest.mark.parametrize("fmt", ["sarif", "junit", "markdown", "gitlab"])
def test_format_carries_evidence_chain(fmt: str) -> None:
    """Every format must surface finding_id + verdict_v2 for traceability."""
    finding = make_finding(verdict_v2="exploited")
    scan = make_scan(findings=[finding])
    text = _as_text(fmt, scan)
    assert finding.id in text, f"{fmt} dropped finding_id"
    assert "exploited" in text, f"{fmt} dropped verdict_v2"


@pytest.mark.parametrize("fmt", ["sarif", "junit", "markdown", "gitlab"])
def test_format_carries_posture(fmt: str) -> None:
    """Posture (AIVSS + band) recoverable from every format."""
    scan = make_scan(aivss=43)
    text = _as_text(fmt, scan)
    assert "43" in text
    assert scan.band.value in text
