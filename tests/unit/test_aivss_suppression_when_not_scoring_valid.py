"""Issue #261 — when ``scoring_valid=False``, numeric AIVSS and per-ASI
scores MUST be suppressed in report.json AND in the run.log "aivss final"
line.

The rc38 matrix shipped ``report.json`` payloads carrying
``aivss=88, band=not_evaluated, findings=0`` simultaneously — the
numeric AIVSS reads as a healthy GOOD score while the band correctly
says ``not_evaluated``. Per-ASI scores defaulted to ``100.0`` for
never-tested boundaries. ``run.log`` printed
``aivss final: score=88 band=GOOD`` while report.json said
``band=not_evaluated``: two contradictory truths from one scan.

Operators screenshot the log line; CI reads the JSON. They must agree.

The fix:

1. ``emit_json`` (the report.json writer) returns ``aivss=None`` and
   ``asi_scores={}`` when ``scoring_valid=False``.
2. The "aivss final:" run.log line is suppressed under the same
   condition, replaced with
   ``aivss final: not_evaluated (scoring_valid=False)``.
3. ``band`` in report.json and the run.log final line always agree.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.reports.json_report import emit_json


def _make_scan(
    *,
    scoring_valid: bool,
    aivss: int = 88,
    band: SeverityBand = SeverityBand.NOT_EVALUATED,
) -> Scan:
    """Build a minimal Scan matching the rc38 quota-incident shape:
    numeric AIVSS retained in-memory (for trend-tracking) but
    ``scoring_valid=False`` + ``band=NOT_EVALUATED`` because the run
    was so degraded the score cannot be trusted."""
    return Scan(
        id="suppress-test",
        package_version="1.0.0rc38",
        aivss_formula_version="2026-06",
        probe_library_version="0.0.0-test",
        target_mode="prompt",
        target_ref="stub",
        tier=Tier.T1_CRITICAL,
        aivss=aivss,
        band=band,
        sub_scores={"a": 0.0, "b": 0.0},
        findings=[],
        asi_scores={cat: 100.0 for cat in AsiCategory},
        duration_seconds=0.0,
        cost_usd=0.0,
        mode="full",
        mode_authoritative=False,
        scoring_valid=scoring_valid,
        evaluation_mode="real",
        created_at=datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC),
    )


def test_report_json_nulls_aivss_when_scoring_not_valid(tmp_path: Path) -> None:
    """``emit_json`` MUST publish ``aivss=None`` when
    ``scoring_valid=False`` so dashboards that read ``headline.aivss``
    without joining ``scoring_valid`` cannot mis-classify a quota-
    failed scan as a healthy 88. The numeric in-memory Scan keeps the
    score for forensic trend-tracking (the existing back-compat
    contract); only the rendered payload is nulled."""
    scan = _make_scan(scoring_valid=False, aivss=88)
    payload = emit_json(scan, sign=False)

    assert payload["aivss"] is None, (
        f"report.json.aivss must be None when scoring_valid=False; got "
        f"{payload['aivss']!r}. Dashboards that read headline.aivss "
        f"without joining scoring_valid otherwise mis-classify quota-"
        f"failed scans as healthy 88s (#261)."
    )
    assert payload["asi_scores"] == {}, (
        f"report.json.asi_scores must be empty when scoring_valid=False "
        f"(defaults to 100.0 for never-tested categories misread as "
        f"perfect coverage); got {payload['asi_scores']!r}."
    )
    # band continues to flow from the Scan model (already NOT_EVALUATED
    # under scoring_valid=False per the finalise() override).
    assert payload["band"] == SeverityBand.NOT_EVALUATED.value
    assert payload["scoring_valid"] is False


def test_report_json_preserves_aivss_when_scoring_valid(tmp_path: Path) -> None:
    """Back-compat: a healthy scan (``scoring_valid=True``) renders the
    numeric ``aivss`` AND the ``asi_scores`` dict unchanged. The
    suppression is ONLY for the not-evaluated case."""
    scan = _make_scan(scoring_valid=True, aivss=72, band=SeverityBand.WARNING)
    payload = emit_json(scan, sign=False)

    assert payload["aivss"] == 72
    assert payload["asi_scores"], "asi_scores must be non-empty when scoring_valid=True"
    assert payload["band"] == SeverityBand.WARNING.value


def test_run_log_final_line_matches_report_json_band(caplog: object) -> None:
    """Contract: the ``aivss final:`` run.log line and ``report.json.band``
    MUST agree. Pre-fix, the swarm emitted
    ``aivss final: score=88 band=GOOD`` while the report rendered
    ``band=not_evaluated`` — two contradictory truths.

    The fix routes the run.log line through the same ``scoring_valid``
    gate as the JSON renderer. When the scan is not authoritative the
    line MUST read ``aivss final: not_evaluated (scoring_valid=False)``
    and MUST NOT contain ``score=N band=GOOD``-style content.
    """
    from agent_guardian.core.swarm import _format_aivss_final_log_line

    scan = _make_scan(scoring_valid=False, aivss=88, band=SeverityBand.NOT_EVALUATED)
    line = _format_aivss_final_log_line(
        scoring_valid=scan.scoring_valid,
        score=scan.aivss,
        band=scan.band,
        penalty=0.0,
        sub_scores=scan.sub_scores,
        tier=scan.tier,
        n_findings=0,
        duration=12.3,
        cost_usd=0.0,
        tokens_total=0,
    )

    assert "score=" not in line, (
        f"run.log final line must NOT carry a numeric score when scoring_valid=False; got {line!r}"
    )
    assert "band=GOOD" not in line, (
        f"run.log final line must NOT advertise a band when scoring_valid=False; got {line!r}"
    )
    assert "not_evaluated" in line.lower() or "not evaluated" in line.lower()
    assert "scoring_valid" in line.lower()


def test_run_log_final_line_preserves_numeric_when_scoring_valid() -> None:
    """Back-compat: a real authoritative scan keeps the numeric run.log
    line so existing forensic tooling that greps ``score=N band=BAND``
    continues to read."""
    from agent_guardian.core.swarm import _format_aivss_final_log_line

    line = _format_aivss_final_log_line(
        scoring_valid=True,
        score=72,
        band=SeverityBand.WARNING,
        penalty=0.0,
        sub_scores={"a": 1.0, "b": 2.0},
        tier=Tier.T1_CRITICAL,
        n_findings=3,
        duration=10.0,
        cost_usd=0.01,
        tokens_total=1234,
    )
    assert "score=72" in line
    assert "band=" in line


def test_unevaluated_scan_run_log_band_matches_report_json(tmp_path: Path) -> None:
    """End-to-end contract: report.json's ``band`` and the run.log
    final line MUST be derivable from the same ``(scoring_valid, band)``
    pair so an operator reading either surface sees the same truth."""
    from agent_guardian.core.swarm import _format_aivss_final_log_line

    scan = _make_scan(scoring_valid=False, aivss=88, band=SeverityBand.NOT_EVALUATED)
    payload = emit_json(scan, sign=False)
    line = _format_aivss_final_log_line(
        scoring_valid=scan.scoring_valid,
        score=scan.aivss,
        band=scan.band,
        penalty=0.0,
        sub_scores=scan.sub_scores,
        tier=scan.tier,
        n_findings=0,
        duration=0.0,
        cost_usd=0.0,
        tokens_total=0,
    )

    report_band = payload["band"]
    # Neither surface may carry a numeric AIVSS line implying GOOD when
    # the other says NOT_EVALUATED.
    if report_band == SeverityBand.NOT_EVALUATED.value:
        assert "GOOD" not in line.upper() or "NOT_EVALUATED" in line.upper()
        assert "score=" not in line
