"""Accessibility + cross-tab navigation coverage.

Locks WAI-ARIA semantics on the tablist (role, aria-selected,
aria-controls, tabindex roving) and exercises keyboard / focus paths
that the smoke suite skipped. These tests guard against the kind of
silent a11y regression that breaks screen-reader users without showing
up in visual review.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

expect.set_options(timeout=5_000)


# ---------------------------------------------------------------------------
# WAI-ARIA tablist semantics — the single source of truth for tab state.
# ---------------------------------------------------------------------------


def test_tablist_carries_role_tablist(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The container of the four tab buttons must declare role=tablist."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator('[data-testid="tabs-tablist"]')).to_have_attribute("role", "tablist")


def test_each_tab_button_has_role_tab(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Every tab button must declare role=tab. Locked because a
    template-level role drop would break screen-reader tab nav."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    for slug in ("overview", "findings", "probes", "logs"):
        expect(page.locator(f'[data-testid="tabs-button-{slug}"]')).to_have_attribute("role", "tab")


def test_each_tab_button_has_aria_controls_pointing_at_panel(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Each tab button must carry aria-controls pointing at the matching
    tabpanel id. Required for proper screen-reader announce-on-switch."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    for slug in ("overview", "findings", "probes", "logs"):
        expect(page.locator(f'[data-testid="tabs-button-{slug}"]')).to_have_attribute(
            "aria-controls", f"tabpanel-{slug}"
        )


def test_tablist_has_only_one_selected_tab_at_a_time(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Exactly ONE tab button may carry aria-selected=true at any moment.
    Locks the roving-selection contract."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    # Default load → Overview selected, three others not.
    selected = page.locator('[role="tab"][aria-selected="true"]')
    expect(selected).to_have_count(1)
    # Click Findings → still exactly one selected.
    page.locator('[data-testid="tabs-button-findings"]').click()
    expect(selected).to_have_count(1)


def test_tablist_roving_tabindex_after_switch(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """After clicking a different tab, the newly-selected tab should
    carry tabindex=0 and the others tabindex=-1 (the roving-tabindex
    keyboard-nav pattern)."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    page.locator('[data-testid="tabs-button-probes"]').click()
    expect(page.locator('[data-testid="tabs-button-probes"]')).to_have_attribute("tabindex", "0")
    expect(page.locator('[data-testid="tabs-button-overview"]')).to_have_attribute("tabindex", "-1")


# ---------------------------------------------------------------------------
# Panels — aria-labelledby points back at the right tab.
# ---------------------------------------------------------------------------


def test_each_tabpanel_has_aria_labelledby_matching_its_tab(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Each tabpanel must reference its tab via aria-labelledby. Locked
    so a tab/panel pair never drifts."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    for slug in ("overview", "findings", "probes", "logs"):
        # Click into the tab so the panel renders (server-rendered
        # ``hidden`` attribute may otherwise hide it from locator).
        page.locator(f'[data-testid="tabs-button-{slug}"]').click()
        expect(page.locator(f"#tabpanel-{slug}")).to_have_attribute(
            "aria-labelledby", f"tab-{slug}"
        )


# ---------------------------------------------------------------------------
# Page-level a11y — landmarks + headings.
# ---------------------------------------------------------------------------


def test_dashboard_page_has_an_h1_or_h2_visible(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The dashboard must have at least one visible heading (h1, h2 or
    h3). Locks "blank page with no heading" regressions."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    headings = page.locator("h1, h2, h3").filter(visible=True)
    # The screen-reader-only h2 on the tablist counts; this is a "any
    # heading rendered at all" sanity check.
    assert headings.count() > 0


def test_home_page_has_a_heading(page: Page, uvicorn_server: str) -> None:
    """The home page must have at least one heading."""
    page.goto(f"{uvicorn_server}/")
    headings = page.locator("h1, h2, h3")
    assert headings.count() > 0
