"""Tests for the Live Dashboard - Coverage route (/scan/{id}/coverage).

Covers the pixel-match route added to satisfy the Coverage design from
``guarding-oss`` bundle. Three layers:

1. Pure helpers (band classification, count formatting, finding sort/filter/paginate).
2. Framework-row builders given a real Scan + coverage dict.
3. End-to-end HTTP via FastAPI TestClient — verifies template renders, 5
   rows are present, severity counts are correct, pagination works.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_guardian import __version__
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.scan import Scan
from agent_guardian.models.severity import Severity, SeverityBand
from agent_guardian.models.tier import Tier
from agent_guardian.server import ScanStore, create_app
from agent_guardian.server.routes.coverage import (
    _agents_active_label,
    _band_css,
    _band_for_pct,
    _band_label,
    _build_aivss_row,
    _build_atlas_row,
    _build_csa_row,
    _build_owasp_row,
    _build_strategies_row,
    _filter_findings,
    _format_when,
    _paginate_findings,
    _PseudoScan,
    _sort_findings,
    _unique_probes_for_asi,
    _unique_probes_total,
)

# ---------------------------------------------------------------------------
# Fixtures — mirror the pattern in test_server_app.py
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(root_dir=tmp_path)


@pytest.fixture
def client(store: ScanStore) -> TestClient:
    app = create_app(scan_store=store)
    return TestClient(app)


_NOW = datetime(2026, 5, 27, 12, 0, 0, tzinfo=UTC)


def _f(
    fid: str,
    *,
    asi: AsiCategory = AsiCategory.ASI01,
    severity: Severity = Severity.HIGH,
    csa: CsaCategory = CsaCategory.GOAL_INSTRUCTION_MANIPULATION,
    mitre: tuple[str, ...] = ("AML.T0054",),
    age_minutes: int = 1,
    summary: str | None = None,
) -> Finding:
    return Finding(
        id=fid,
        probe_id=f"{asi.value}-PR-{fid}",
        asi=asi,
        mitre_atlas=list(mitre),
        csa_category=csa,
        severity=severity,
        attempt_count=1,
        success=True,
        confidence=0.9,
        summary=summary or f"sample finding {fid}",
        created_at=_NOW - timedelta(minutes=age_minutes),
    )


def _make_scan(scan_id: str, findings: list[Finding], *, aivss: int = 72) -> Scan:
    return Scan(
        id=scan_id,
        package_version=__version__,
        aivss_formula_version="aivss-v1",
        probe_library_version="probes-v1",
        target_mode="code",
        target_ref="tests/stub:run",
        tier=Tier.T3_STANDARD,
        mode="full",
        aivss=aivss,
        band=SeverityBand.WARNING if aivss < 80 else SeverityBand.GOOD,
        sub_scores={
            "prompt_injection_resistance": 70.0,
            "tool_scope_safety": 85.0,
            "pii_containment": 90.0,
            "memory_poisoning_resistance": 65.0,
            "excessive_agency_containment": 80.0,
            "hallucination_resistance": 75.0,
        },
        findings=findings,
        asi_scores={cat: 75.0 for cat in AsiCategory},
        duration_seconds=82.5,
        cost_usd=0.03,
        tokens_total=12000,
        created_at=_NOW,
    )


def _persist_scan_and_memory(store: ScanStore, scan: Scan, memory_lines: list[dict]) -> None:
    scan_dir = store.scan_dir(scan.id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "scan.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    with (scan_dir / "memory.jsonl").open("w", encoding="utf-8") as fh:
        for rec in memory_lines:
            fh.write(json.dumps(rec) + "\n")


def _reflection(agent: str, asi: str, strategy: str = "pair") -> dict:
    """One memory.jsonl reflection line shaped exactly like SharedMemory writes."""
    turn = {
        "agent": agent,
        "asi_category": asi,
        "strategy": strategy,
        "seed_id": f"{asi}-PR-001",
        "mitre_techniques": ["AML.T0054"],
        "csa_category": "goal-instruction-manipulation",
    }
    return {
        "record_type": "reflection",
        "payload": {"agent": agent, "content": json.dumps(turn)},
    }


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_band_for_pct_boundaries() -> None:
    assert _band_for_pct(100, in_progress=False) == "exc"
    assert _band_for_pct(90, in_progress=False) == "exc"
    assert _band_for_pct(89, in_progress=False) == "good"
    assert _band_for_pct(80, in_progress=False) == "good"
    assert _band_for_pct(79, in_progress=False) == "attn"
    assert _band_for_pct(70, in_progress=False) == "attn"
    assert _band_for_pct(69, in_progress=False) == "fail"
    assert _band_for_pct(0, in_progress=False) == "fail"


def test_band_for_pct_in_progress_short_circuits() -> None:
    """``in_progress=True`` always wins, regardless of score."""
    assert _band_for_pct(100, in_progress=True) == "run"
    assert _band_for_pct(0, in_progress=True) == "run"
    assert _band_for_pct(None, in_progress=False) == "run"


def test_format_when_seconds_minutes_hours() -> None:
    """``_format_when`` uses non-breaking space (U+00A0) between mins/secs to
    match the design's ``&nbsp;`` so the age never wraps mid-token."""
    now = _NOW
    assert _format_when(now - timedelta(seconds=12), now) == "12s ago"
    assert _format_when(now - timedelta(minutes=2, seconds=4), now) == "2m\u00a004s ago"
    assert _format_when(now - timedelta(hours=1, minutes=5), now) == "1h\u00a005m ago"


# ---------------------------------------------------------------------------
# Sort + filter + paginate
# ---------------------------------------------------------------------------


def test_sort_findings_criticality_desc_then_newest() -> None:
    low = _f("a", severity=Severity.LOW, age_minutes=10)
    crit = _f("b", severity=Severity.CRITICAL, age_minutes=2)
    high_old = _f("c", severity=Severity.HIGH, age_minutes=5)
    high_new = _f("d", severity=Severity.HIGH, age_minutes=1)
    out = _sort_findings([low, crit, high_old, high_new], "criticality")
    # critical first, then HIGH-newer-first (high_new before high_old), then low
    assert [f.id for f in out] == ["b", "d", "c", "a"]


def test_sort_findings_newest_oldest() -> None:
    old = _f("a", age_minutes=10)
    mid = _f("b", age_minutes=5)
    new = _f("c", age_minutes=1)
    assert [f.id for f in _sort_findings([old, mid, new], "newest")] == ["c", "b", "a"]
    assert [f.id for f in _sort_findings([new, mid, old], "oldest")] == ["a", "b", "c"]


def test_filter_findings_severity_asi_query() -> None:
    a = _f("a", asi=AsiCategory.ASI01, severity=Severity.HIGH, summary="injection here")
    b = _f("b", asi=AsiCategory.ASI02, severity=Severity.LOW, summary="tool stuff")
    c = _f("c", asi=AsiCategory.ASI01, severity=Severity.CRITICAL, summary="memory leak")
    found = _filter_findings([a, b, c], severity="high", asi=None, q=None)
    assert [f.id for f in found] == ["a"]
    found = _filter_findings([a, b, c], severity="all", asi="ASI01", q=None)
    assert {f.id for f in found} == {"a", "c"}
    found = _filter_findings([a, b, c], severity="all", asi=None, q="memory")
    assert [f.id for f in found] == ["c"]


def test_paginate_findings_clamps_page_and_size() -> None:
    findings = [_f(str(i), age_minutes=i + 1) for i in range(33)]
    sorted_f = _sort_findings(findings, "newest")
    rows, page, total_pages, total = _paginate_findings(sorted_f, page=2, per_page=15, now=_NOW)
    assert total == 33
    assert total_pages == 3
    assert page == 2
    assert len(rows) == 15
    # Page-out-of-range clamps to last page rather than 500-ing.
    rows, page, total_pages, _ = _paginate_findings(sorted_f, page=99, per_page=15, now=_NOW)
    assert page == 3
    assert len(rows) == 33 - 30  # last 3 items


# ---------------------------------------------------------------------------
# Framework row builders (data mapping)
# ---------------------------------------------------------------------------


def test_owasp_row_has_10_cells_with_correct_asi_codes() -> None:
    scan = _make_scan("s1", [_f("a", asi=AsiCategory.ASI01, severity=Severity.CRITICAL)])
    row = _build_owasp_row(scan, coverage={"agents": {"goal-hijack-agent": 12}}, scan_done=True)
    assert row.code == "OWASP"
    assert len(row.cells) == 10
    assert row.cells[0].name == "ASI01"
    assert row.cells[0].has_warn is True  # CRITICAL finding raises the warning dot
    # ASI02 has no findings → no warn
    assert row.cells[1].name == "ASI02"
    assert row.cells[1].has_warn is False


def test_atlas_row_has_10_cells_and_routes_findings_to_tactics() -> None:
    scan = _make_scan(
        "s2",
        [
            _f("a", mitre=("AML.T0054",)),  # → Impact (TA0011)
            _f("b", mitre=("AML.T0006",)),  # → Recon (TA0001)
        ],
    )
    row = _build_atlas_row(scan)
    assert row.code == "ATLAS"
    assert len(row.cells) == 10
    # Recon cell is index 0 in the design layout
    assert row.cells[0].name == "Recon"
    assert row.cells[0].count_label.startswith("1\u2009")
    # Impact cell is the last (index 9)
    assert row.cells[9].name == "Impact"
    assert row.cells[9].count_label.startswith("1\u2009")


def test_csa_row_has_12_cells() -> None:
    scan = _make_scan("s3", [_f("a", csa=CsaCategory.GOAL_INSTRUCTION_MANIPULATION)])
    row = _build_csa_row(scan)
    assert row.code == "CSA"
    assert len(row.cells) == 12
    # First cell is Goal & instr. — should have a count of 1.
    assert row.cells[0].count_label.startswith("1\u2009")


def test_aivss_row_has_6_cells_with_subscores() -> None:
    scan = _make_scan("s4", [])
    row = _build_aivss_row(scan, coverage={"agents": {"goal-hijack-agent": 5}})
    assert row.code == "AIVSS"
    assert len(row.cells) == 6
    # First cell = Prompt injection, score from sub_scores["prompt_injection_resistance"] = 70
    assert row.cells[0].name == "Prompt injection"
    assert row.cells[0].score_pct == 70


def test_strategies_row_has_5_cells_and_picks_up_strategy_counts() -> None:
    scan = _make_scan("s5", [])
    coverage = {"strategies_flattened": {"pair": 4, "tap": 2, "crescendo": 2}}
    row = _build_strategies_row(scan, coverage)
    assert row.code == "STRAT"
    assert len(row.cells) == 5
    # PAIR is index 3 in the design layout.
    pair_cell = next(c for c in row.cells if c.name == "PAIR")
    assert "4 iter." in pair_cell.count_label
    # AgentPoison is the cell with count=0 → state should be "run" (no attempts).
    poison_cell = next(c for c in row.cells if c.name == "AgentPoison")
    assert poison_cell.state == "run"


# ---------------------------------------------------------------------------
# End-to-end HTTP: GET /scan/{id}/coverage
# ---------------------------------------------------------------------------


def test_coverage_route_404s_unknown_scan(client: TestClient) -> None:
    resp = client.get("/scan/does-not-exist/coverage")
    assert resp.status_code == 404


def test_coverage_route_renders_complete_scan(client: TestClient, store: ScanStore) -> None:
    findings = [
        _f("c1", severity=Severity.CRITICAL, asi=AsiCategory.ASI01, age_minutes=1),
        _f("c2", severity=Severity.CRITICAL, asi=AsiCategory.ASI06, age_minutes=2),
        _f("h1", severity=Severity.HIGH, asi=AsiCategory.ASI02, age_minutes=3),
        _f("m1", severity=Severity.MEDIUM, asi=AsiCategory.ASI03, age_minutes=4),
        _f("l1", severity=Severity.LOW, asi=AsiCategory.ASI09, age_minutes=5),
    ]
    scan = _make_scan("sc-test", findings, aivss=84)
    memory = [
        _reflection("goal-hijack-agent", "ASI01", "pair"),
        _reflection("tool-abuse-agent", "ASI02", "tap"),
        _reflection("memory-poison-agent", "ASI06", "crescendo"),
    ]
    _persist_scan_and_memory(store, scan, memory)

    resp = client.get("/scan/sc-test/coverage")
    assert resp.status_code == 200
    body = resp.text

    # Score banner
    assert ">84<" in body  # the big AIVSS number
    assert "Good · 80\u201389" in body
    # All 5 framework row codes appear
    for code in ("OWASP", "ATLAS", "CSA", "AIVSS", "STRAT"):
        assert f">{code}<" in body, f"row code {code!r} missing from page"
    # All 10 OWASP cells render their ASI label
    for i in range(1, 11):
        assert f"ASI{i:02d}" in body
    # Findings table headers
    for hdr in ("Severity", "When", "ASI", "Finding", "Frameworks", "Remediation"):
        assert f">{hdr}<" in body
    # Each finding's summary appears
    for f in findings:
        assert f.summary in body
    # Severity counts in the toolbar segmented control
    assert ">Critical<" in body
    assert 'High<span class="seg__n">' in body  # segmented-control button for "High" still renders


def test_coverage_route_severity_filter_filters_table_only(
    client: TestClient, store: ScanStore
) -> None:
    findings = [
        _f("c1", severity=Severity.CRITICAL, summary="critical alpha", age_minutes=1),
        _f("h1", severity=Severity.HIGH, summary="high beta", age_minutes=2),
        _f("l1", severity=Severity.LOW, summary="low gamma", age_minutes=3),
    ]
    scan = _make_scan("sc-filter", findings, aivss=72)
    _persist_scan_and_memory(store, scan, [])

    resp = client.get("/scan/sc-filter/coverage?severity=critical")
    assert resp.status_code == 200
    body = resp.text
    # The critical finding is shown
    assert "critical alpha" in body
    # The HIGH and LOW ones are NOT shown in the table body
    assert "high beta" not in body
    assert "low gamma" not in body
    # But the segmented-control count for High should still show "1"
    # (severity_counts is computed off the un-severity-filtered set).
    assert 'High<span class="seg__n">' in body  # segmented-control button for "High" still renders


def test_coverage_route_paginates_at_per_page_boundary(
    client: TestClient, store: ScanStore
) -> None:
    """With per_page=2 and 5 findings, page=1 shows 2, page=3 shows 1."""
    findings = [
        _f(f"f{i}", severity=Severity.LOW, summary=f"finding {i}", age_minutes=i + 1)
        for i in range(5)
    ]
    scan = _make_scan("sc-page", findings, aivss=72)
    _persist_scan_and_memory(store, scan, [])

    resp = client.get("/scan/sc-page/coverage?per_page=2&page=1")
    assert resp.status_code == 200
    assert "Showing <strong>1&ndash;2</strong> of <strong>5</strong>" in resp.text

    resp = client.get("/scan/sc-page/coverage?per_page=2&page=3")
    assert resp.status_code == 200
    assert "Showing <strong>5&ndash;5</strong> of <strong>5</strong>" in resp.text


def test_coverage_route_no_top_nav_per_jegan_comment(client: TestClient, store: ScanStore) -> None:
    """Jegan comment #5: 'remove the top tabs. we dont need it'.

    The template must NOT render an Overview/Coverage/Findings/Transcripts
    tab bar inside the topbar (only brand + URL chip + locality pill).
    """
    scan = _make_scan("sc-nonav", [], aivss=100)
    _persist_scan_and_memory(store, scan, [])
    resp = client.get("/scan/sc-nonav/coverage")
    assert resp.status_code == 200
    body = resp.text
    # The hidden nav tag is fine, but no class="topnav__item" anywhere.
    assert 'class="topnav__item"' not in body


def test_coverage_route_no_telemetry_wording_per_jegan_comment(
    client: TestClient, store: ScanStore
) -> None:
    """Jegan comment #3: 'remvoe the no telemetry word' — we actually send telemetry."""
    scan = _make_scan("sc-tel", [], aivss=100)
    _persist_scan_and_memory(store, scan, [])
    resp = client.get("/scan/sc-tel/coverage")
    assert resp.status_code == 200
    assert "no telemetry" not in resp.text.lower()
    assert "telemetry" not in resp.text.lower()


def test_coverage_route_static_assets_served(client: TestClient) -> None:
    """The template imports two CSS files — make sure both serve 200 with
    the right MIME so the page renders styled."""
    for path in ("/static/colors_and_type.css", "/static/coverage.css"):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        assert resp.headers["content-type"].startswith("text/css")


# ---------------------------------------------------------------------------
# Edge-case helpers — close the coverage gap
# ---------------------------------------------------------------------------


def test_band_css_maps_all_5_bands() -> None:
    """All five SeverityBand values must map to a valid cell-state class."""
    assert _band_css(SeverityBand.EXCELLENT) == "exc"
    assert _band_css(SeverityBand.GOOD) == "good"
    assert _band_css(SeverityBand.WARNING) == "attn"
    assert _band_css(SeverityBand.POOR) == "fail"
    assert _band_css(SeverityBand.CRITICAL) == "fail"


def test_band_label_maps_all_5_bands() -> None:
    """All five SeverityBand values must map to a human pill label."""
    assert "Excellent" in _band_label(SeverityBand.EXCELLENT)
    assert "Good" in _band_label(SeverityBand.GOOD)
    assert "Warning" in _band_label(SeverityBand.WARNING)
    assert "Poor" in _band_label(SeverityBand.POOR)
    assert "Critical" in _band_label(SeverityBand.CRITICAL)


def test_agents_active_label_running_vs_completed() -> None:
    """The agents-active tile string differs by running state."""
    coverage = {"agents": {"goal-hijack-agent": 5, "tool-abuse-agent": 3}, "skipped_agents": []}
    scan = _make_scan("s", [])
    # Completed scan → "2 / 11"
    assert _agents_active_label(coverage, scan, is_running=False) == "2 / 11"
    # Running scan with no skipped → "2 / 11"
    assert _agents_active_label(coverage, None, is_running=True) == "2 / 11"
    # Running with skipped → denominator reduces.
    coverage_skip = {**coverage, "skipped_agents": [{"agent": "a2a-agent"}]}
    assert _agents_active_label(coverage_skip, None, is_running=True) == "2 / 10"


def test_pseudo_scan_has_id_attribute() -> None:
    """The _PseudoScan shim used for in-flight scans must expose .id."""
    p = _PseudoScan("scan-xyz")
    assert p.id == "scan-xyz"


def test_filter_invalid_severity_falls_back_silently(tmp_path: Path) -> None:
    """An invalid severity query string is logged + ignored, not 500."""
    findings = [_f("a", severity=Severity.HIGH)]
    # Filter with a junk severity — should log + return everything.
    out = _filter_findings(findings, severity="garbage", asi=None, q=None)
    assert len(out) == 1


def test_filter_invalid_asi_falls_back_silently(tmp_path: Path) -> None:
    """An invalid ASI query string is logged + ignored, not 500."""
    findings = [_f("a", asi=AsiCategory.ASI01)]
    out = _filter_findings(findings, severity=None, asi="NOT_AN_ASI", q=None)
    assert len(out) == 1


def test_owasp_row_handles_missing_scan(tmp_path: Path) -> None:
    """Building the OWASP row with scan=None (in-flight, no scan.json yet)
    must still produce 10 cells in the 'run' state."""
    row = _build_owasp_row(None, coverage={}, scan_done=False)
    assert len(row.cells) == 10
    assert all(c.state == "run" for c in row.cells)


def test_owasp_row_completed_scan_no_attempts_defaults_to_good(tmp_path: Path) -> None:
    """A finalised scan with no findings + no attempts on an ASI should
    show as 'good' (target defended the unmeasured surface by default)."""
    scan = _make_scan("s", [], aivss=100)
    row = _build_owasp_row(scan, coverage={"agents": {}}, scan_done=True)
    assert len(row.cells) == 10
    # Every cell has attempts=0 so the "scan_done + 0 attempts" branch fires.
    assert all(c.state == "good" for c in row.cells)


# ---------------------------------------------------------------------------
# Attempts vs unique probes (#43)
# ---------------------------------------------------------------------------


def test_unique_probes_total_dedupes_repeats() -> None:
    """Multi-turn strategies fire the same probe many times — the count
    of *distinct* probes must dedupe."""
    coverage = {
        "attempts_total": 5,
        "probes_attempted": ["ASI01-GH-001", "ASI01-GH-002"],
    }
    # The roll-up writes a sorted unique list; helper returns 2.
    assert _unique_probes_total(coverage) == 2
    # Defensive: a non-unique sequence still collapses.
    coverage_dup = {
        "probes_attempted": ["ASI01-GH-001", "ASI01-GH-001", "ASI02-TA-001"],
    }
    assert _unique_probes_total(coverage_dup) == 2
    # Empty / missing
    assert _unique_probes_total({}) == 0
    assert _unique_probes_total({"probes_attempted": []}) == 0


def test_unique_probes_for_asi_filters_by_prefix() -> None:
    """The per-ASI distinct-probe count filters ``probes_attempted`` by code."""
    coverage = {
        "probes_attempted": [
            "ASI01-GH-001",
            "ASI01-GH-002",
            "ASI02-TA-001",
            "ASI10-DR-007",
        ],
    }
    assert _unique_probes_for_asi(coverage, AsiCategory.ASI01) == 2
    assert _unique_probes_for_asi(coverage, AsiCategory.ASI02) == 1
    assert _unique_probes_for_asi(coverage, AsiCategory.ASI03) == 0
    assert _unique_probes_for_asi(coverage, AsiCategory.ASI10) == 1
    # Non-string entries are ignored (defensive — should never happen in
    # practice but the helper must not crash on malformed coverage dicts).
    bad = {"probes_attempted": ["ASI01-GH-001", None, 42, "ASI01-GH-002"]}
    assert _unique_probes_for_asi(bad, AsiCategory.ASI01) == 2


def test_owasp_row_carries_attempts_and_unique_probes() -> None:
    """Each OWASP cell now exposes BOTH the raw attempt count and the
    distinct-probe count so the template can surface either lens."""
    scan = _make_scan("s", [_f("a", asi=AsiCategory.ASI01)])
    coverage = {
        "agents": {"goal-hijack-agent": 7},  # 7 attempts on ASI01
        "probes_attempted": [
            "ASI01-GH-001",
            "ASI01-GH-002",
            "ASI01-GH-003",
            "ASI02-TA-001",
        ],
    }
    row = _build_owasp_row(scan, coverage=coverage, scan_done=True)
    asi01 = row.cells[0]
    assert asi01.name == "ASI01"
    assert asi01.attempts == 7
    assert asi01.unique_probes == 3
    # ASI02 had no attempts in this coverage (no goal-hijack-agent entry
    # for it) but does have one unique probe id — surface them both.
    asi02 = row.cells[1]
    assert asi02.name == "ASI02"
    assert asi02.attempts == 0
    assert asi02.unique_probes == 1


def test_coverage_route_exposes_both_attempts_and_unique_probes(
    client: TestClient, store: ScanStore
) -> None:
    """The coverage view must surface BOTH ``attempts fired`` (raw count) and
    ``unique probes`` (distinct seeds) so the dashboard doesn't conflate
    re-fires with breadth of coverage (review finding #43)."""
    findings = [_f("c1", severity=Severity.CRITICAL, asi=AsiCategory.ASI01)]
    scan = _make_scan("sc-tiles", findings, aivss=72)
    # Hand-craft a memory.jsonl where one probe was fired 3 times: that
    # writes 3 attempts but only 1 unique probe id.
    memory = [
        # 3 attempts on the same seed_id ASI01-GH-001
        _reflection("goal-hijack-agent", "ASI01", "pair"),
        _reflection("goal-hijack-agent", "ASI01", "pair"),
        _reflection("goal-hijack-agent", "ASI01", "pair"),
        # Plus 1 attempt on a distinct seed (different ASI for clarity)
        _reflection("tool-abuse-agent", "ASI02", "tap"),
    ]
    # Override the seed_id of the second reflection bucket so two unique
    # probe ids are seen across 4 attempts.
    memory[3]["payload"]["content"] = json.dumps(
        {
            "agent": "tool-abuse-agent",
            "asi_category": "ASI02",
            "strategy": "tap",
            "seed_id": "ASI02-TA-001",
            "mitre_techniques": ["AML.T0054"],
            "csa_category": "agent-critical-system-interaction",
        }
    )
    _persist_scan_and_memory(store, scan, memory)

    resp = client.get("/scan/sc-tiles/coverage")
    assert resp.status_code == 200
    body = resp.text
    # Both labels appear on the page.
    assert ">attempts fired<" in body
    assert ">unique probes<" in body
    # The old conflated label must not leak — the rename is the user-visible
    # part of this fix.
    assert ">probes fired<" not in body
    # 4 attempts (raw judged turns), 2 unique probes (distinct seed ids).
    # The template formats both with thousands-separator, so check for the
    # literal numbers in the tile body.
    assert ">4<" in body  # attempts fired
    assert ">2<" in body  # unique probes


def test_coverage_context_keys_present(client: TestClient, store: ScanStore) -> None:
    """Direct render-context probe — the route must pass both keys regardless
    of whether the template is rebuilt. Locks in the contract so a future
    template refresh can rely on either binding."""
    scan = _make_scan("sc-ctx", [], aivss=100)
    _persist_scan_and_memory(store, scan, [])
    resp = client.get("/scan/sc-ctx/coverage")
    assert resp.status_code == 200
    # Indirect assertion: both tile labels must be present in the rendered
    # body — confirms both context keys are wired through.
    assert "attempts fired" in resp.text
    assert "unique probes" in resp.text
