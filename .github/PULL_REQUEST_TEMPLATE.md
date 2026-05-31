<!--
Thanks for the PR. A few hard requirements before it can merge:

  * Every commit must carry `Signed-off-by:` (DCO). Use `git commit -s`.
    Unsigned commits are rejected by CI and cannot be merged.
  * Conventional Commit prefix on each commit (`feat:`, `fix:`, `chore:`,
    `docs:`, `test:`, `refactor:`). See CONTRIBUTING.md.
  * Tests must cover the change. CI runs `ruff`, `mypy`, `pytest`,
    `bandit`, `semgrep`, `gitleaks`, and the link-check.

For security vulnerabilities, stop and file a private report via
GitHub Security Advisories instead. See SECURITY.md.
-->

## Summary

<!-- One paragraph: what changed and why. -->

## Linked issue / discussion

<!-- Closes #NNN, or "n/a" with a one-line justification. -->

## Type of change

<!-- Tick all that apply. -->

- [ ] `feat` — new user-facing feature
- [ ] `fix` — bug fix
- [ ] `chore` — non-user-facing maintenance
- [ ] `docs` — documentation only
- [ ] `test` — tests only
- [ ] `refactor` — internal restructuring with no behaviour change

## Surface touched

- [ ] Probe corpus (`src/agent_guardian/probes/`)
- [ ] ASI agent or strategy (`src/agent_guardian/agents/`, `strategies/`)
- [ ] Adapter (`src/agent_guardian/adapters/`, `transports/`)
- [ ] LLM provider (`src/agent_guardian/llm/`)
- [ ] Report writer (`src/agent_guardian/reports/`)
- [ ] CLI (`src/agent_guardian/cli.py`)
- [ ] Server / dashboard (`src/agent_guardian/server/`)
- [ ] Build / release tooling (`.github/workflows/`, `pyproject.toml`)
- [ ] Docs only

## How this was tested

<!-- Commands you ran locally, plus the relevant new or updated test paths. -->

```bash
uv run pytest tests/...
uv run ruff check .
uv run mypy src/
```

## Checklist

- [ ] Every commit carries `Signed-off-by:` (DCO).
- [ ] Commit messages use Conventional Commit prefixes.
- [ ] Tests added or updated; full suite (`uv run pytest`) is green locally.
- [ ] `ruff`, `mypy`, and `pre-commit` are clean locally.
- [ ] `CHANGELOG.md` updated under `[Unreleased]` for any user-visible change.
- [ ] Public-API additions or breaking changes are noted in the PR description.
- [ ] No secrets, credentials, or customer data in the diff.

## Maintainer notes (optional)

<!-- Anything reviewers should know that isn't obvious from the diff. -->
