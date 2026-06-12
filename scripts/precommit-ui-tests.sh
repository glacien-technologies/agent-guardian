#!/usr/bin/env bash
# Pre-commit hook: run the Playwright E2E suite ONLY when dashboard files
# have changed in the staged diff. Exits 0 fast when no UI files are
# touched so devs working on the backend never see this fire.
#
# Configured in .pre-commit-config.yaml via the ``files:`` pattern; this
# script is the second-layer safety net (skip-on-no-relevant-change) +
# the env-var wrap (AGENT_GUARDIAN_TEST_HOOKS=1).

set -euo pipefail

# The pre-commit framework already filtered to UI files via its `files:`
# regex. If none made it through, exit clean.
if [[ $# -eq 0 ]]; then
  echo "ui-e2e: no dashboard files staged — skipping"
  exit 0
fi

# Confirm Playwright + Chromium are installed. Soft-skip if they aren't,
# so the hook never blocks a commit on infrastructure-not-installed —
# the developer can opt in by running ``playwright install chromium``.
if ! .venv/bin/python -c "import playwright" >/dev/null 2>&1; then
  echo "ui-e2e: Playwright not installed in .venv — skipping."
  echo "        run 'uv pip install playwright pytest-playwright && playwright install chromium' to enable."
  exit 0
fi

# Run the e2e suite against a fresh uvicorn subprocess (conftest handles it).
# AGENT_GUARDIAN_TEST_HOOKS=1 is required for the /test/* router to mount.
echo "ui-e2e: running ${#@} changed UI files through Playwright smoke suite"
AGENT_GUARDIAN_TEST_HOOKS=1 .venv/bin/python -m pytest tests/e2e/ -q --tb=short
