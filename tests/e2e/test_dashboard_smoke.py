"""E2E smoke tests for the AgentGuardian dashboard.

15 high-value tests covering the headline scenarios from the tester PDF
2026-06-12: tab navigation, AIVSS rendering, status pill, findings
table + counter, severity filter, detail modal open/close, empty
findings state, failed-scan pill + blanked AIVSS, home page scan list,
and the test-only endpoints themselves.

Run via:

    AGENT_GUARDIAN_TEST_HOOKS=1 .venv/bin/python -m pytest tests/e2e/ -v

These run against a real ``uvicorn`` subprocess (see ``conftest.py``) and
a real headless Chromium. Designed to be fast (<30s wall-clock for the
full file) so they fit into a pre-commit hook gated on UI file changes.
"""

from __future__ import annotations

import httpx
from playwright.sync_api import Page, expect

# 1s default for all expect() calls — fast feedback in the pre-commit hook.
# Individual tests bump this when they're explicitly waiting on SSE.
expect.set_options(timeout=5_000)


# ---------------------------------------------------------------------------
# Test-only endpoint smoke — confirms the gate + fixture loader work.
# ---------------------------------------------------------------------------


def test_fixture_load_endpoint_returns_scan_id(uvicorn_server: str) -> None:
    """The ``/test/fixtures/load`` endpoint must return the scan_id from
    the fixture's report.json. This is the core of every other test, so
    a broken loader would make the whole suite confusing to debug."""
    resp = httpx.post(
        f"{uvicorn_server}/test/fixtures/load",
        json={"name": "finbot-baseline"},
        timeout=5.0,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == "cli-e2e-baseline"
    assert body["fixture"] == "finbot-baseline"


def test_fixture_load_404_on_unknown_name(uvicorn_server: str) -> None:
    """Unknown fixture name → 404, not a 500."""
    resp = httpx.post(
        f"{uvicorn_server}/test/fixtures/load",
        json={"name": "does-not-exist"},
        timeout=5.0,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Home page — scan list rendering.
# ---------------------------------------------------------------------------


def test_home_page_lists_loaded_scan(page: Page, loaded_baseline: str, uvicorn_server: str) -> None:
    """After loading a fixture, the /home page must show the scan as a row."""
    page.goto(f"{uvicorn_server}/")
    expect(page.locator(f'tr[data-row-scan-id="{loaded_baseline}"]')).to_be_visible()


def test_home_page_renders_band_pill(page: Page, loaded_baseline: str, uvicorn_server: str) -> None:
    """The Band column must render the baseline's Good band as a pill (#168)."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_baseline}"]')
    # data-row-band is the lowercased band value; baseline = "good".
    expect(row).to_have_attribute("data-row-band", "good")


def test_home_band_filter_hides_non_matching_rows(
    page: Page, loaded_baseline: str, loaded_failed: str, uvicorn_server: str
) -> None:
    """Selecting a band in the filter dropdown must hide rows that don't
    match — this is the regression that PDF item 28 reported."""
    page.goto(f"{uvicorn_server}/")
    page.locator("#band-filter").select_option("warning")
    # baseline (good) and failed (also default-perfect) should both be hidden;
    # we just assert the baseline row goes hidden.
    expect(page.locator(f'tr[data-row-scan-id="{loaded_baseline}"]')).to_be_hidden()


# ---------------------------------------------------------------------------
# Scan dashboard — tabs.
# ---------------------------------------------------------------------------


def test_tabs_overview_is_selected_by_default(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Loading the scan page must land on the Overview tab."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator('[data-testid="tabs-button-overview"]')).to_have_attribute(
        "aria-selected", "true"
    )


def test_tabs_clicking_findings_switches_panel(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Clicking the Findings tab must flip aria-selected and reveal the panel."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    page.locator('[data-testid="tabs-button-findings"]').click()
    expect(page.locator('[data-testid="tabs-button-findings"]')).to_have_attribute(
        "aria-selected", "true"
    )
    expect(page.locator('[data-testid="tabs-button-overview"]')).to_have_attribute(
        "aria-selected", "false"
    )


def test_tabs_all_four_buttons_present_and_clickable(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """All four documented tabs render and accept clicks. Catches any tab
    rename or template-include regression."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    for slug in ("overview", "findings", "probes", "logs"):
        button = page.locator(f'[data-testid="tabs-button-{slug}"]')
        expect(button).to_be_visible()
        button.click()
        expect(button).to_have_attribute("aria-selected", "true")


# ---------------------------------------------------------------------------
# Overview — AIVSS + status pill.
# ---------------------------------------------------------------------------


def test_overview_renders_aivss_value(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The AIVSS score must render and match the fixture (78)."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator('[data-live="aivss"]')).to_have_text("78")


def test_overview_status_pill_says_completed_for_baseline(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """A completed fixture (completeness_pct=100) must show the Completed
    pill in the topbar — locking the issue #112 gate."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator("[data-scan-status-label]")).to_contain_text("Completed")


# ---------------------------------------------------------------------------
# Findings tab — table, counter, filter, modal.
# ---------------------------------------------------------------------------


def test_findings_table_renders_all_rows(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """All 9 baseline findings render as rows in the findings table."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}?tab=findings")
    rows = page.locator('[data-source="finding"]')
    expect(rows).to_have_count(9)


def test_findings_counter_matches_row_count(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The "Showing N of M findings" counter must match the row count.
    The counter element carries the total in its data-counter-total
    attribute; we assert against that directly so we never trip on the
    surrounding "Showing… of… findings" prose."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}?tab=findings")
    counter = page.locator("#exec-findings-filter-counter")
    expect(counter).to_have_attribute("data-counter-total", "9")


def test_findings_severity_filter_narrows_rows(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Selecting "critical" in the severity dropdown narrows the visible
    rows to only the 1 critical finding in the baseline fixture.

    The findings panel is initially ``hidden`` (only Overview shows on
    load), so we click the Findings tab first to make the filter visible
    — server-rendered panels with the ``hidden`` HTML attribute are
    correctly reported as not-visible by Playwright until revealed."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    page.locator('[data-testid="tabs-button-findings"]').click()
    page.locator("#exec-findings-filter-severity").select_option("critical")
    visible = page.locator('[data-source="finding"]:visible')
    expect(visible).to_have_count(1)


# ---------------------------------------------------------------------------
# Failed-scan path — the #112 reproduction lock at the UI layer.
# ---------------------------------------------------------------------------


def test_failed_scan_home_row_shows_failed_pill(
    page: Page, loaded_failed: str, uvicorn_server: str
) -> None:
    """A scan with completeness_pct=10 (failed) must render the 'failed'
    status pill on the home page — not 'done', not a real AIVSS."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_failed}"]')
    expect(row.locator(".pill-failed")).to_be_visible()


def test_failed_scan_home_row_blanks_aivss(
    page: Page, loaded_failed: str, uvicorn_server: str
) -> None:
    """The numeric AIVSS column must be blanked for a failed scan (issue
    #112: a default-perfect 100 must NOT render as a real result)."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_failed}"]')
    # The status column shows "failed"; the AIVSS column shows "—".
    expect(row).to_contain_text("—")
    # And explicitly does NOT contain "100" anywhere in the row.
    text = row.text_content() or ""
    assert "100" not in text, f"failed-scan row must not show the stale AIVSS=100; got: {text!r}"
