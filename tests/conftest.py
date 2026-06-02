# Test configuration lands in M2.
#
# Defensive: pin a wide COLUMNS for tests that shell out to Typer's
# ``CliRunner`` and assert on literal flag substrings (e.g.
# ``"--recon-budget-seconds" in result.stdout``). On CI the runner
# reports a narrow fallback terminal, and rich/click will line-wrap long
# option names mid-token, breaking those assertions. The CLI itself
# already pins ``max_content_width=200`` in ``cli.py`` for belt-and-braces
# robustness; setting COLUMNS here is an additional, harmless layer that
# costs nothing if the CLI override is in place.
import os
import shutil

import pytest

os.environ.setdefault("COLUMNS", "200")


@pytest.fixture(autouse=True, scope="session")
def _wide_terminal_for_cli_runner():
    # Rich/Typer help-text rendering depends on COLUMNS at runtime.
    # CliRunner does not set this by default, so on narrow CI terminals
    # flag names like --recon-budget-seconds get truncated with ellipsis
    # and `"--recon-budget-seconds" in result.stdout` assertions fail.
    #
    # The module-level ``setdefault`` above handles the common case where
    # COLUMNS is unset; this fixture *unconditionally* overrides any narrow
    # value that the CI runner injects after import (e.g. via pytest-xdist
    # workers or a parent shell that exports COLUMNS=80). NO_COLOR is also
    # forced so Rich does not emit ANSI escapes that can sneak into the
    # substring assertions.
    old = {k: os.environ.get(k) for k in ("COLUMNS", "NO_COLOR")}
    os.environ["COLUMNS"] = "200"
    os.environ["NO_COLOR"] = "1"
    yield
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ---------------------------------------------------------------------------
# Pass-5 durable fix: monkeypatch shutil.get_terminal_size at the system layer.
#
# Pass-4 set COLUMNS=200 + NO_COLOR=1 + TERM=dumb at the env-var layer, but
# CI logs proved this was insufficient:
#   - Click's CliRunner does NOT propagate COLUMNS to the wrapped command's
#     terminal_width detection. It calls shutil.get_terminal_size() directly,
#     which on CI sandboxes returns the OS-level fallback (80, 24) regardless
#     of what's in os.environ.
#   - Rich similarly derives its wrap width from shutil.get_terminal_size()
#     when stdout is captured (no real TTY), and ignores NO_COLOR in some
#     captured-stdout configurations -- ANSI escape codes still appear in
#     result.stdout, breaking substring asserts on flag names.
#
# The only durable fix is to monkeypatch shutil.get_terminal_size itself,
# so EVERY code path (Click, Rich, custom formatters) sees a wide terminal.
# Function-scoped so each test gets a clean patch lifecycle via monkeypatch.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _force_wide_terminal_for_click(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force shutil.get_terminal_size to report a wide terminal for every test.

    Click/Rich derive their wrap width from shutil.get_terminal_size() at
    help-render time. CliRunner does NOT propagate COLUMNS to Click, so the
    only durable fix is monkeypatching shutil itself. We also re-force the
    env vars here (the session fixture sets them once, but pytest-xdist or
    nested CliRunner invocations can mutate them mid-test).
    """
    monkeypatch.setattr(
        shutil,
        "get_terminal_size",
        lambda fallback=(80, 24): os.terminal_size((200, 24)),
    )
    # Also force these for any subprocess-shell-based help renders that
    # bypass the in-process shutil patch.
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "dumb")  # disables Rich ANSI on any code path
