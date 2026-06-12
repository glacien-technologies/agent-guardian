"""Findings tab — deep coverage beyond the smoke suite.

Locks each filter dimension, filter composition (AND), and the
clear-filter restore behaviour. Each filter narrows independently;
multi-filter selections AND together. All assertions read against the
baseline fixture (9 findings, 1 critical, 3 high, 3 medium, 2 low).
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

expect.set_options(timeout=5_000)


def _open_findings(page: Page, base_url: str, scan_id: str) -> None:
    """Navigate to the scan page and click the Findings tab."""
    page.goto(f"{base_url}/scan/{scan_id}")
    page.locator('[data-testid="tabs-button-findings"]').click()


# ---------------------------------------------------------------------------
# Severity filter — extends the smoke test with the other three buckets.
# ---------------------------------------------------------------------------


def test_findings_severity_filter_high_shows_three(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The baseline carries 3 High-severity findings; selecting High in
    the filter must surface exactly those."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-severity").select_option("high")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(3)


def test_findings_severity_filter_medium_shows_three(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """3 Medium findings in the baseline."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-severity").select_option("medium")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(3)


def test_findings_severity_filter_low_shows_two(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """2 Low-severity findings in the baseline."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-severity").select_option("low")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(2)


def test_findings_severity_filter_clear_restores_all(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Selecting the empty "All severities" option restores the full
    9-row visible set."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    sev = page.locator("#exec-findings-filter-severity")
    sev.select_option("critical")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(1)
    sev.select_option("")  # value="" = "All severities"
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(9)


# ---------------------------------------------------------------------------
# ASI filter — distinct from severity. The baseline has findings under
# ASI01 (x2), ASI02, ASI03, ASI05, ASI06, ASI08, ASI09, ASI10 — 8 unique.
# ---------------------------------------------------------------------------


def test_findings_asi_filter_lists_present_categories_only(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The ASI dropdown must only list ASI categories that have at least
    one finding in the page — no dead options."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    options = page.locator("#exec-findings-filter-asi option")
    # 8 unique ASI categories + 1 "All ASI" empty-value option.
    expect(options).to_have_count(9)


def test_findings_asi_filter_asi01_shows_two(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """ASI01 has 2 findings (f-001 High + f-002 Medium); the filter must
    narrow to exactly those."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-asi").select_option("ASI01")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(2)


def test_findings_asi_filter_asi03_shows_one(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """ASI03 has 1 finding (f-004 Critical)."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-asi").select_option("ASI03")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(1)


# ---------------------------------------------------------------------------
# Probe filter — distinct from ASI; each probe_id is its own row.
# ---------------------------------------------------------------------------


def test_findings_probe_filter_narrows_to_single(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Filtering by a specific probe id must surface only that one row."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-probe").select_option("ASI03-PA-001")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(1)


# ---------------------------------------------------------------------------
# Filter composition — multiple filters AND together.
# ---------------------------------------------------------------------------


def test_findings_severity_and_asi_filters_compose(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Severity=High + ASI=ASI01 must narrow to the single high+asi01
    finding (f-001) — proving that filters AND together rather than OR."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-severity").select_option("high")
    page.locator("#exec-findings-filter-asi").select_option("ASI01")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(1)


def test_findings_no_match_filters_show_zero_rows(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Filtering by ASI03 + severity=Low yields zero rows (ASI03 has only
    a Critical). The visible count must collapse to zero without
    erroring."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-severity").select_option("low")
    page.locator("#exec-findings-filter-asi").select_option("ASI03")
    expect(page.locator('[data-source="finding"]:visible')).to_have_count(0)


# ---------------------------------------------------------------------------
# Counter reflects active filter.
# ---------------------------------------------------------------------------


def test_findings_counter_updates_when_filter_narrows(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The visible-count span (``data-counter-visible``) must reflect the
    active filter — locks the counter ↔ filter coupling."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-severity").select_option("critical")
    expect(page.locator("[data-counter-visible]").first).to_have_text("1")


def test_findings_counter_total_stays_at_nine(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The TOTAL span must stay at 9 even when the filter narrows — total
    is the unfiltered universe, not the visible count. Uses the
    SPAN-with-data-counter-total inside the wrapper, not the wrapper
    div (which also carries the attribute as its own data-counter-total)."""
    _open_findings(page, uvicorn_server, loaded_baseline)
    page.locator("#exec-findings-filter-severity").select_option("high")
    expect(page.locator("span[data-counter-total]")).to_have_text("9")
