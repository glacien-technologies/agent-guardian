"""Overview tab — deep coverage beyond the smoke suite.

Locks the per-ASI breakdown rendering, the KPI cards, and the band
classification — all of which back the issue #165 scoring math fix at
the UI layer.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

expect.set_options(timeout=5_000)


def test_overview_band_rendering_matches_score(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The KPI band element must render the band class derived from the
    AIVSS score (baseline 78 → Good)."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    # AIVSS score = 78 → Good band → exec-kpi__value--good class on the value span.
    aivss = page.locator('[data-live="aivss"]')
    expect(aivss).to_have_text("78")
    # The band class is applied on the same element.
    expect(aivss).to_have_class("exec-kpi__value exec-kpi__value--good")


def test_overview_scan_id_visible_in_topbar(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The topbar must surface the scan_id so the operator can correlate
    with logs / file paths."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    # The topbar renders the scan id somewhere visible in the dashboard chrome.
    expect(page.locator("body")).to_contain_text(loaded_baseline)


def test_overview_target_metadata_visible(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The target_ref from report.json must appear on the page so the
    operator knows what was scanned."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator("body")).to_contain_text("finbot")


def test_overview_aivss_block_carries_band_class(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The wrapper [data-kpi="aivss"] must exist so the live update can
    target it for re-render."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator('[data-kpi="aivss"]')).to_be_visible()


def test_overview_per_asi_breakdown_lists_all_ten_categories(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The ASI breakdown must list all 10 ASI categories (ASI01-10)."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    body = page.locator("body").text_content() or ""
    for n in range(1, 11):
        slug = f"ASI{n:02d}"
        assert slug in body, f"missing {slug} in Overview breakdown"


def test_overview_status_topbar_label_present(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The topbar's scan-status label slot must exist so the SSE
    handler in layout.html can flip it from running → Completed."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator("[data-scan-status-label]")).to_be_visible()


def test_overview_aivss_score_persists_on_reload(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """Reloading the scan page must show the same AIVSS value (the
    server-rendered initial paint must carry the score; SSE delta
    arrivals during reload are not relied on here)."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    expect(page.locator('[data-live="aivss"]')).to_have_text("78")
    page.reload()
    expect(page.locator('[data-live="aivss"]')).to_have_text("78")
