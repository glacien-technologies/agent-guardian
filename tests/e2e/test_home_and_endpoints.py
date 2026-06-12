"""Home page deep-coverage + test-endpoint coverage.

Locks the home-page columns rendering, multi-scan filtering, and the
remaining test-only endpoints (``events.replay``, ``crash``) that the
smoke suite did not exercise.
"""

from __future__ import annotations

import httpx
from playwright.sync_api import Page, expect

expect.set_options(timeout=5_000)


# ---------------------------------------------------------------------------
# Home page columns + multi-row interaction.
# ---------------------------------------------------------------------------


def test_home_page_renders_aivss_column_for_baseline(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The /home AIVSS column for a completed scan must show the score
    (78 for the baseline) — the numeric column is the operator's
    at-a-glance score."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_baseline}"]')
    text = row.text_content() or ""
    assert "78" in text, f"baseline AIVSS=78 must appear in row text, got: {text!r}"


def test_home_page_renders_target_ref_for_baseline(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The /home Target column must show the scan's target_ref so the
    operator can identify what was scanned without clicking through."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_baseline}"]')
    expect(row).to_contain_text("finbot.example.com")


def test_home_page_renders_done_pill_for_baseline(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """A completed scan must show a "done" pill, not "running" or
    "failed" — distinguishes the three terminal-status branches in
    ``_derive_status``."""
    page.goto(f"{uvicorn_server}/")
    row = page.locator(f'tr[data-row-scan-id="{loaded_baseline}"]')
    expect(row.locator(".pill-done")).to_be_visible()


def test_home_page_band_filter_default_is_all_bands(page: Page, uvicorn_server: str) -> None:
    """The band-filter dropdown's initial value is empty (= "All bands"),
    so the table shows every row by default."""
    page.goto(f"{uvicorn_server}/")
    sel = page.locator("#band-filter")
    expect(sel).to_have_value("")


def test_home_page_lists_baseline_and_failed_simultaneously(
    page: Page, loaded_baseline: str, loaded_failed: str, uvicorn_server: str
) -> None:
    """When both fixtures are loaded the table must show TWO rows. Catches
    a single-row regression in the listing logic."""
    page.goto(f"{uvicorn_server}/")
    expect(page.locator(f'tr[data-row-scan-id="{loaded_baseline}"]')).to_be_visible()
    expect(page.locator(f'tr[data-row-scan-id="{loaded_failed}"]')).to_be_visible()


# ---------------------------------------------------------------------------
# Test-only endpoints — coverage for events.replay and crash.
# ---------------------------------------------------------------------------


def test_events_replay_endpoint_returns_event_stream(
    loaded_baseline: str, uvicorn_server: str
) -> None:
    """``GET /test/scan/{id}/events.replay`` must return text/event-stream
    and yield at least one event for a fixture that ships an
    events.jsonl. The /test prefix matches the router's mount point."""
    with httpx.stream(
        "GET",
        f"{uvicorn_server}/test/scan/{loaded_baseline}/events.replay",
        timeout=5.0,
    ) as resp:
        assert resp.status_code == 200
        assert resp.headers.get("content-type", "").startswith("text/event-stream")
        # Stream the first chunk to confirm we got SSE-formatted data.
        body_bytes = b""
        for chunk in resp.iter_bytes():
            body_bytes += chunk
            if len(body_bytes) > 100:
                break
        body = body_bytes.decode("utf-8", errors="replace")
        assert "event:" in body, f"expected SSE 'event:' line in: {body!r}"


def test_events_replay_404_when_no_events_jsonl(loaded_failed: str, uvicorn_server: str) -> None:
    """A fixture without events.jsonl (the failed fixture) must return 404
    from the replay endpoint — not 500, not an empty stream."""
    resp = httpx.get(
        f"{uvicorn_server}/test/scan/{loaded_failed}/events.replay",
        timeout=5.0,
    )
    assert resp.status_code == 404


def test_crash_endpoint_flips_status_to_failed(loaded_baseline: str, uvicorn_server: str) -> None:
    """``POST /test/scan/{id}/crash`` must return 200 and set the
    internal status to failed. Subsequent /home requests should then
    render the failed pill."""
    resp = httpx.post(
        f"{uvicorn_server}/test/scan/{loaded_baseline}/crash",
        timeout=5.0,
    )
    assert resp.status_code == 200
    assert resp.json()["new_status"] == "failed"


def test_crash_endpoint_404_on_unknown_scan(uvicorn_server: str) -> None:
    """Crashing an unknown scan id must 404 (not 500, not silently
    succeed)."""
    resp = httpx.post(
        f"{uvicorn_server}/test/scan/does-not-exist/crash",
        timeout=5.0,
    )
    assert resp.status_code == 404


def test_fixture_load_endpoint_with_failed_fixture(uvicorn_server: str) -> None:
    """The fixture loader handles the failed fixture path too — locks
    that the second fixture in the corpus is still loadable."""
    resp = httpx.post(
        f"{uvicorn_server}/test/fixtures/load",
        json={"name": "finbot-failed"},
        timeout=5.0,
    )
    assert resp.status_code == 200
    assert resp.json()["scan_id"] == "cli-e2e-failed"
