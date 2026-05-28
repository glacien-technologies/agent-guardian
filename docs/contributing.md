# Contributing

Thank you for considering a contribution to AgentGuardian. We welcome bug reports, new probes, new adapters, documentation improvements, and pull requests of every shape.

The canonical, always-up-to-date contributing guide lives at [`CONTRIBUTING.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/CONTRIBUTING.md) at the repository root. This page is a high-level orientation — read the canonical file for full details before opening a PR.

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
| Add a new probe                              | [Concepts → Probes](concepts/probes.md) and [`src/agent_guardian/probes/asiNN/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/probes) |
| Add a new ASI agent                          | `CONTRIBUTING.md` § *How to add an ASI agent* + [Concepts → Swarm](concepts/swarm.md)             |
| Add a new framework adapter                  | [`src/agent_guardian/adapters/framework/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/adapters/framework) |
| Add a new LLM provider                       | [`src/agent_guardian/llm/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/llm) — subclass `BaseLLM` |
| Improve documentation                        | Edit any page under `docs/`; `mkdocs serve` for live preview. See [Releasing to PyPI](publishing.md) for site deploys. |

## Reporting security issues

**Do not file security reports as public GitHub issues.** Follow the responsible-disclosure policy in [`SECURITY.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/SECURITY.md).

## Code of conduct

All contributors are expected to follow the project's code of conduct (see `CODE_OF_CONDUCT.md` if present, or default to the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)).
