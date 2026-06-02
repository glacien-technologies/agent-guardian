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
