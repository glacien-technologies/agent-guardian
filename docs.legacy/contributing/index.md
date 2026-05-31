# Contributing

> **TL;DR.** AgentGuardian welcomes bug reports, new probes, new adapters, docs improvements, and pull requests. This page is the high-level orientation — read the canonical [`CONTRIBUTING.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/CONTRIBUTING.md) at the repo root for full rules before opening a PR.

## At a glance

- **DCO required.** Every commit must carry a `Signed-off-by:` trailer. Add it with `git commit -s`. No CLA — DCO 1.1 is sufficient. CI rejects unsigned commits.
- **Branch naming**: `feat/`, `fix/`, `chore/`, `docs/`, `test/`. Example: `feat/asi04-tool-poisoning-langchain`.
- **Conventional Commits**: prefix matches the branch (`feat:`, `fix:`, etc.). Release notes are generated from these prefixes.
- **All four checks must pass locally before opening a PR**: `ruff check .`, `mypy src/`, `pytest`, `pre-commit run --all-files`. CI runs these on Python 3.10–3.13.

## Local development

```bash
git clone https://github.com/glacien-technologies/agent-guardian.git
cd agent-guardian

# uv (recommended) — single command, full env
uv sync --all-extras --extra dev
uv run pytest
uv run ruff check .
uv run mypy src/
uv run pre-commit install
uv run pre-commit run --all-files
```

Or with vanilla pip:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,docs,full,aws]"
pytest && ruff check . && mypy src/
```

## Where to start

| You want to…                                | Look at…                                                                                          |
|---------------------------------------------|---------------------------------------------------------------------------------------------------|
| Add a new probe                              | [Authoring a probe](probe-authoring.md) + [Concepts → Probes](../concepts/probes.md)              |
| Add a new framework adapter                  | [Authoring an adapter](adapter-authoring.md)                                                      |
| Add a new LLM provider                       | [`src/agent_guardian/llm/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/llm) — subclass `BaseLLM` |
| Improve documentation                        | Edit any page under `docs/`; preview with `uv run mkdocs serve`. See [Deploying the docs site](site-deployment.md). |
| Cut a release                                | [Releasing to PyPI](releasing.md)                                                                 |
| Understand our engineering rules             | [Engineering standards](engineering-standards.md)                                                 |
| Understand the deprecation cadence           | [Deprecation policy](deprecation-policy.md)                                                       |
| Understand how decisions get made            | [Governance](governance.md)                                                                       |
| Ship the v1.0 launch                         | [v1.0 Launch Checklist](operator-checklist.md) (maintainers only)                                  |

## Reporting security issues

**Do not file security reports as public GitHub issues.** Follow the responsible-disclosure policy in [`SECURITY.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/SECURITY.md) (also rendered in-site at [Security → Responsible disclosure](../security/responsible-disclosure.md)).

## Code of conduct

All contributors are expected to follow the project's [Code of Conduct](https://github.com/glacien-technologies/agent-guardian/blob/main/CODE_OF_CONDUCT.md), based on the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Report violations to <conduct@glacien.ai>.
