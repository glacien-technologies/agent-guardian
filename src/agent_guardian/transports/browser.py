"""Browser transport (Stage 4, optional) — drive a headless web UI.

A :class:`BrowserTransport` exercises a chat agent that has *no* API — only a
web UI. It drives a headless browser via Playwright: navigate to ``url``, type
the adversarial prompt into ``input_selector``, submit (click ``submit_selector``
or press Enter), wait for the reply to appear, then read the text of
``output_selector`` back as the :class:`Response`. Like every other transport it
is built from **primitives** (a url + a handful of CSS selectors), never from a
Contract.

Playwright is an OPTIONAL, heavy dependency (it pulls a browser binary too). It
is imported lazily; when the Python package is absent the constructor raises a
clear :class:`ImportError` naming the ``agent-guardian[browser]`` extra. We use
Playwright's **async** API so the transport stays cooperative on the event loop.

:meth:`send` never raises for a transport fault — navigation timeouts, missing
selectors and Playwright errors are caught and mapped onto our
:class:`TransportError` taxonomy, returned in the :class:`Response`.

Session handling:

* ``stateless`` (default) — a fresh browser context + page is created per
  :meth:`send` and torn down afterwards, so each turn is isolated.
* persistent — call :meth:`open_session` first to launch one browser + page and
  reuse it across sends (the page state, and therefore any in-UI conversation
  history, persists) until :meth:`close_session` / :meth:`aclose`.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from agent_guardian.llm.errors import (
    LLMError,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
)
from agent_guardian.transports.base import (
    CapabilityReport,
    Request,
    Response,
    Transport,
)
from agent_guardian.transports.errors import map_llm_error

__all__ = ["BrowserTransport"]

_LOG = logging.getLogger(__name__)

# Remediation surfaced when the optional ``playwright`` dependency is absent.
_MISSING_DEP_MSG = (
    "BrowserTransport requires the 'playwright' package, which is not installed. "
    "Install it with: pip install 'agent-guardian[browser]' "
    "(then run 'playwright install chromium' to fetch the browser binary)."
)


def _load_playwright() -> Any:
    """Import and return Playwright's ``async_playwright`` entry point.

    The dependency is optional + heavy (extra ``browser``); we import it lazily
    so the base install never pays the cost. When absent we raise an
    :class:`ImportError` whose message names the remediation extra and the
    ``playwright install`` follow-up step.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        _LOG.debug("browser transport: 'playwright' import failed (%s)", exc)
        raise ImportError(_MISSING_DEP_MSG) from exc
    return async_playwright


class BrowserTransport(Transport):
    """Headless-browser transport that drives a chat web UI via Playwright."""

    kind: ClassVar[str] = "browser"

    def __init__(
        self,
        *,
        url: str,
        input_selector: str,
        output_selector: str,
        submit_selector: str | None = None,
        submit_with_enter: bool = False,
        wait_for_selector: str | None = None,
        nav_timeout_ms: int = 30000,
        action_timeout_ms: int = 30000,
        headless: bool = True,
        browser_name: str = "chromium",
    ) -> None:
        if not url:
            raise ValueError("BrowserTransport requires a non-empty url")
        if not input_selector:
            raise ValueError("BrowserTransport requires an input_selector")
        if not output_selector:
            raise ValueError("BrowserTransport requires an output_selector")
        if submit_selector is None and not submit_with_enter:
            raise ValueError(
                "BrowserTransport requires either a submit_selector or submit_with_enter=True"
            )
        # Fail fast at construction when the optional dependency is missing.
        self._async_playwright = _load_playwright()

        self._url = url
        self._input_selector = input_selector
        self._output_selector = output_selector
        self._submit_selector = submit_selector
        self._submit_with_enter = submit_with_enter
        # Default the post-submit readiness wait to the output selector itself.
        self._wait_for_selector = wait_for_selector or output_selector
        self._nav_timeout_ms = nav_timeout_ms
        self._action_timeout_ms = action_timeout_ms
        self._headless = headless
        self._browser_name = browser_name

        # Persistent session handles (populated by :meth:`open_session`).
        self._playwright: Any = None
        self._browser: Any = None
        self._page: Any = None

    @property
    def url(self) -> str:
        return self._url

    # ---- browser plumbing --------------------------------------------------

    def _timeout_errors(self) -> tuple[type[BaseException], ...]:
        """Return the Playwright error classes treated as timeouts/faults.

        Resolved lazily so the optional import only happens once Playwright is
        present. The ``Error`` base covers selector/navigation failures; the
        ``TimeoutError`` subclass is mapped to our timeout category.
        """
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError

        return (PlaywrightTimeoutError, PlaywrightError)

    async def _launch(self) -> tuple[Any, Any, Any]:
        """Start Playwright, launch the browser, and open one page."""
        playwright = await self._async_playwright().start()
        browser_type = getattr(playwright, self._browser_name)
        browser = await browser_type.launch(headless=self._headless)
        page = await browser.new_page()
        page.set_default_timeout(self._action_timeout_ms)
        page.set_default_navigation_timeout(self._nav_timeout_ms)
        return playwright, browser, page

    async def _drive_page(self, page: Any, prompt: str) -> str:
        """Run the navigate→fill→submit→read flow on ``page``.

        Mapped Playwright faults bubble up as :class:`LLMError` subclasses; the
        caller (:meth:`send`) folds them into a :class:`Response`.
        """
        timeout_err, generic_err = self._timeout_errors()
        try:
            await page.goto(self._url, timeout=self._nav_timeout_ms)
            await page.fill(self._input_selector, prompt, timeout=self._action_timeout_ms)
            if self._submit_selector is not None:
                await page.click(self._submit_selector, timeout=self._action_timeout_ms)
            else:
                await page.press(self._input_selector, "Enter", timeout=self._action_timeout_ms)
            await page.wait_for_selector(self._wait_for_selector, timeout=self._action_timeout_ms)
            text = await page.text_content(self._output_selector, timeout=self._action_timeout_ms)
        except timeout_err as exc:
            raise LLMTimeoutError(f"browser: timed out driving page: {exc}") from exc
        except generic_err as exc:
            raise LLMTransientError(f"browser: page interaction failed: {exc}") from exc

        if text is None:
            raise LLMResponseFormatError(
                f"browser: output_selector {self._output_selector!r} matched no text"
            )
        return str(text)

    # ---- Transport surface -------------------------------------------------

    async def send(self, request: Request) -> Response:
        """Drive one turn through the web UI. Never raises for transport faults."""
        try:
            if self._page is not None:
                text = await self._drive_page(self._page, request.prompt)
            else:
                text = await self._send_ephemeral(request.prompt)
            return Response(text=text, raw=text)
        except LLMError as exc:
            _LOG.debug("browser transport: send failed (%s)", exc)
            return Response(error=map_llm_error(exc))

    async def _send_ephemeral(self, prompt: str) -> str:
        """Launch a throwaway browser, drive it, and tear it down."""
        playwright, browser, page = await self._launch()
        try:
            return await self._drive_page(page, prompt)
        finally:
            await self._teardown(playwright, browser)

    async def _teardown(self, playwright: Any, browser: Any) -> None:
        """Close ``browser`` then stop ``playwright``, swallowing close faults."""
        close_errors = self._timeout_errors()
        for closer, label in ((browser, "browser"), (playwright, "playwright")):
            if closer is None:
                continue
            close_fn = getattr(closer, "close", None) or getattr(closer, "stop", None)
            if close_fn is None:
                continue
            try:
                await close_fn()
            except close_errors as exc:
                _LOG.debug("browser transport: error closing %s (%s)", label, exc)

    async def open_session(self) -> None:
        """Launch a persistent browser + page reused by later sends."""
        if self._page is None:
            self._playwright, self._browser, self._page = await self._launch()

    async def close_session(self) -> None:
        """Tear down the persistent browser opened by :meth:`open_session`."""
        if self._page is not None or self._browser is not None or self._playwright is not None:
            await self._teardown(self._playwright, self._browser)
            self._playwright = None
            self._browser = None
            self._page = None

    async def aclose(self) -> None:
        await self.close_session()

    def describe(self) -> CapabilityReport:
        """Report this browser transport's static capabilities.

        A web UI is non-streaming and exposes no tool calls to scrape; it can run
        stateless (fresh page per turn) or replay client history in-UI across a
        persistent session.
        """
        return CapabilityReport(
            kind=self.kind,
            streaming=False,
            supports_tools=False,
            session_modes=("stateless", "client_history"),
            auth_scheme=None,
            endpoint=self._url,
        )
