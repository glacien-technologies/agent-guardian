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

os.environ.setdefault("COLUMNS", "200")
