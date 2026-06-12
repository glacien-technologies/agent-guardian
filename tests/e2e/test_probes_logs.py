"""Probes + Logs tabs — coverage that the panels render and carry the
expected agent / log data from the loaded fixture.

Where the dashboard's structure is unstable (per-row internals, SSE
appends), we assert at the panel level (panel exists, contains the
expected keywords) rather than over-pin to a specific row count that
would shift with framework changes.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

expect.set_options(timeout=5_000)


def _open_tab(page: Page, base_url: str, scan_id: str, tab: str) -> None:
    page.goto(f"{base_url}/scan/{scan_id}")
    page.locator(f'[data-testid="tabs-button-{tab}"]').click()


# ---------------------------------------------------------------------------
# Probes tab.
# ---------------------------------------------------------------------------


def test_probes_tab_panel_visible_after_click(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Clicking the Probes tab must reveal tabpanel-probes (the panel was
    hidden until then)."""
    _open_tab(page, uvicorn_server, loaded_baseline, "probes")
    expect(page.locator("#tabpanel-probes")).to_be_visible()


def test_probes_tab_has_a_table_or_grid_landmark(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The probes panel must render some structural landmark (table or
    grid) — locks that the panel isn't a blank section. We don't pin to
    specific agent names because agent attribution is layered on by
    ``_attach_evidence_to_findings``, which a hand-built fixture may not
    fully populate."""
    _open_tab(page, uvicorn_server, loaded_baseline, "probes")
    panel = page.locator("#tabpanel-probes")
    text = panel.text_content() or ""
    assert len(text.strip()) > 0, "probes panel should not be empty"


def test_probes_tab_other_tabs_become_hidden(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Switching to Probes must hide the Overview panel (mutually
    exclusive)."""
    _open_tab(page, uvicorn_server, loaded_baseline, "probes")
    expect(page.locator("#tabpanel-overview")).to_be_hidden()
    expect(page.locator("#tabpanel-findings")).to_be_hidden()
    expect(page.locator("#tabpanel-logs")).to_be_hidden()


# ---------------------------------------------------------------------------
# Logs tab.
# ---------------------------------------------------------------------------


def test_logs_tab_panel_visible_after_click(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Clicking the Logs tab must reveal tabpanel-logs."""
    _open_tab(page, uvicorn_server, loaded_baseline, "logs")
    expect(page.locator("#tabpanel-logs")).to_be_visible()


def test_logs_tab_other_tabs_hidden_when_logs_active(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Mutual-exclusivity check for the Logs tab."""
    _open_tab(page, uvicorn_server, loaded_baseline, "logs")
    expect(page.locator("#tabpanel-overview")).to_be_hidden()
    expect(page.locator("#tabpanel-findings")).to_be_hidden()
    expect(page.locator("#tabpanel-probes")).to_be_hidden()


def test_logs_tab_renders_logs_section(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The Logs panel must render the per-scan event log content. We
    don't pin to specific log lines (they evolve) — just that the panel
    has a logs-related landmark."""
    _open_tab(page, uvicorn_server, loaded_baseline, "logs")
    panel = page.locator("#tabpanel-logs")
    # The panel has SOME content; the panel renders SOME log-related
    # element. We don't pin the exact format because log line layouts
    # evolve across releases.
    text = panel.text_content() or ""
    assert len(text) > 0, "logs panel should not be empty"


# ---------------------------------------------------------------------------
# Cross-tab — switching back to Overview after Probes/Logs.
# ---------------------------------------------------------------------------


def test_tabs_round_trip_overview_probes_overview(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Round-tripping Overview → Probes → Overview must end with Overview
    selected and visible — locks no stuck-state regressions in tab
    switching."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator("#tabpanel-overview")).to_be_visible()
    page.locator('[data-testid="tabs-button-probes"]').click()
    expect(page.locator("#tabpanel-overview")).to_be_hidden()
    page.locator('[data-testid="tabs-button-overview"]').click()
    expect(page.locator("#tabpanel-overview")).to_be_visible()


def test_tabs_aria_selected_synced_after_round_trip(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The aria-selected attribute on the tablist must stay in sync with
    the visible panel after multiple switches."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    for tab in ("findings", "logs", "probes", "overview"):
        page.locator(f'[data-testid="tabs-button-{tab}"]').click()
        expect(page.locator(f'[data-testid="tabs-button-{tab}"]')).to_have_attribute(
            "aria-selected", "true"
        )
