"""During-scan SSE coverage — drives synthetic events into the cached
EventSource via the ``window.__ag_test_dispatch_sse`` test hook added
to ``static/streams.js``.

The hook synthesises a real ``MessageEvent`` of the right type on the
EventSource that ``live-append.js`` is already subscribed to, so the
test exercises the production handlers end-to-end without standing up
a real backend scan. This is the cheapest faithful reproduction of the
during-scan UI behaviour we can build.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

expect.set_options(timeout=5_000)


def _open_scan_and_warm_sse(page: Page, base_url: str, scan_id: str) -> None:
    """Open the scan page and call AGStreams.events() so the EventSource
    is connected + cached before we try to synthesise events on it.

    The dashboard's own modules already invoke ``AGStreams.events(...)`` at
    boot, so this just ensures the source is registered in the cache."""
    page.goto(f"{base_url}/scan/{scan_id}")
    # Trigger the cached EventSource if no module already did.
    page.evaluate(f"window.AGStreams && window.AGStreams.events({scan_id!r})")


def test_test_dispatch_hook_is_available_on_window(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The Playwright test hook ``window.__ag_test_dispatch_sse`` must be
    present on every dashboard page. Without it the rest of this file is
    untestable, so we lock its existence here first."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    has_hook = page.evaluate("typeof window.__ag_test_dispatch_sse === 'function'")
    assert has_hook, "window.__ag_test_dispatch_sse must be defined for E2E driving"


def test_sse_dispatch_returns_false_when_no_source_yet(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """When no EventSource has been cached yet for the scan, the hook
    must return ``false`` (not throw) — lets the test know the scan's
    SSE wiring hasn't initialised, rather than silently no-oping."""
    page.goto(f"{uvicorn_server}/scan/{loaded_baseline}")
    # Try a scan id we haven't opened — no cached source.
    result = page.evaluate("window.__ag_test_dispatch_sse('definitely-not-loaded', 'finding', {})")
    assert result is False


def test_sse_dispatch_returns_true_after_eventsource_warmed(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """After AGStreams.events() runs (warming the cache), dispatching a
    synthetic event must return ``true``. This is the foundation of
    every other SSE test — without it, no live-append driving works."""
    _open_scan_and_warm_sse(page, uvicorn_server, loaded_baseline)
    result = page.evaluate(
        f"window.__ag_test_dispatch_sse({loaded_baseline!r}, 'scan_done', "
        "{aivss: 78, band: 'Good', findings: 9})"
    )
    assert result is True


def test_sse_listener_fires_on_dispatched_event(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """A listener attached to the cached EventSource must fire when the
    test hook dispatches an event of that kind. Locks the
    dispatchEvent → addEventListener contract that all live-append
    handlers rely on."""
    _open_scan_and_warm_sse(page, uvicorn_server, loaded_baseline)
    fired = page.evaluate(
        f"""
        (() => {{
            return new Promise((resolve) => {{
                const es = window.AGStreams.events({loaded_baseline!r});
                let count = 0;
                es.addEventListener('probe_done', () => {{ count += 1; }});
                window.__ag_test_dispatch_sse({loaded_baseline!r}, 'probe_done', {{n: 1}});
                window.__ag_test_dispatch_sse({loaded_baseline!r}, 'probe_done', {{n: 2}});
                window.__ag_test_dispatch_sse({loaded_baseline!r}, 'probe_done', {{n: 3}});
                setTimeout(() => resolve(count), 50);
            }});
        }})()
        """
    )
    assert fired == 3, f"expected 3 probe_done dispatches to fire, got {fired}"


def test_sse_dispatch_messageevent_carries_payload(
    page: Page, loaded_baseline: str, uvicorn_server: str
) -> None:
    """The synthetic MessageEvent must carry the JSON-encoded payload as
    its data field, so addEventListener handlers receive the right
    shape. We attach an ad-hoc listener via page.evaluate, dispatch the
    event, and read back what the listener captured."""
    _open_scan_and_warm_sse(page, uvicorn_server, loaded_baseline)
    captured = page.evaluate(
        f"""
        (() => {{
            return new Promise((resolve) => {{
                const es = window.AGStreams.events({loaded_baseline!r});
                es.addEventListener('finding', (ev) => resolve(ev.data));
                window.__ag_test_dispatch_sse({loaded_baseline!r}, 'finding', {{
                    finding_id: 'f-test-001',
                    severity: 'CRITICAL'
                }});
            }});
        }})()
        """
    )
    assert "f-test-001" in captured, f"expected payload echo in event data, got: {captured!r}"
