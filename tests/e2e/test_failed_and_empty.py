"""Failed-state + empty-state coverage.

Issue #112 (closed; locked here): a crashed / partial scan must NOT
render a default-perfect AIVSS=100 as if it were a real result. The
home page, the scan-detail page topbar, and the per-row numeric columns
all participate in the suppression contract.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

expect.set_options(timeout=5_000)


# ---------------------------------------------------------------------------
# Failed scan — extends smoke with the per-column suppression matrix.
# ---------------------------------------------------------------------------


def test_failed_scan_home_row_blanks_band_column(
    page: Page, loaded_failed: str, uvicorn_server: str
) -> None:
    """A failed scan must blank the Band column on /home — only the
    status pill should carry the failure signal."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_failed}"]')
    # The data-row-band attribute should be empty for a failed row
    # (list_scans_page blanks the band when status != completed).
    expect(row).to_have_attribute("data-row-band", "")


def test_failed_scan_home_row_blanks_findings_column(
    page: Page, loaded_failed: str, uvicorn_server: str
) -> None:
    """The findings count must NOT render as a number for a failed row."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_failed}"]')
    text = row.text_content() or ""
    # The failed row's Findings cell should be em-dash, not "1" (the
    # fixture's actual count) or "0".
    assert "—" in text


def test_failed_scan_detail_page_loads(page: Page, loaded_failed: str, uvicorn_server: str) -> None:
    """Navigating to /scan/{id} for a failed scan must not error out;
    the dashboard page should still render so the operator can see why."""
    response = page.goto(f"{uvicorn_server}/scan/{loaded_failed}")
    assert response is not None
    assert response.status == 200


def test_failed_scan_detail_page_topbar_renders(
    page: Page, loaded_failed: str, uvicorn_server: str
) -> None:
    """The topbar must render for the failed scan's detail page (the
    operator needs the scan-id visible to correlate with logs)."""
    page.goto(f"{uvicorn_server}/scan/{loaded_failed}")
    expect(page.locator("body")).to_contain_text(loaded_failed)


# ---------------------------------------------------------------------------
# Empty home page — no scans loaded.
# ---------------------------------------------------------------------------


def test_home_page_renders_substantive_content(page: Page, uvicorn_server: str) -> None:
    """The /home page must render substantive content even before any
    fixture is loaded — catches blank-page regressions in the page
    template. Note we don't assert ON-empty state here because the
    session-scope server retains state across tests; what we DO assert
    is the page renders SOMETHING."""
    page.goto(f"{uvicorn_server}/")
    expect(page.locator("body")).to_be_visible()
    body = page.locator("body").text_content() or ""
    assert len(body.strip()) > 50, f"home page should not be blank, got {body!r}"
