# Install

AgentGuardian is published on PyPI as [`agent-guardian`](https://pypi.org/project/agent-guardian/) and supports Python 3.10, 3.11, 3.12, and 3.13 on Linux, macOS, and Windows.

## Standard install

```bash
pip install agent-guardian
```

The base install is intentionally lean — it gives you the CLI, the swarm, the bundled probe corpus, the deterministic stub LLM, the JSON / SARIF / JUnit / Markdown reporters, and the local dashboard. Everything else is opt-in via [extras](#optional-extras) so you don't pay install cost for features you won't use.

Verify the install:

```bash
agent-guardian doctor
```

`doctor` prints the version, the resolved Python interpreter, any LLM API keys it detected in your environment, and the state / config directory locations.

## Optional extras

Install one or more extras with the standard `pip install 'agent-guardian[<extra>]'` syntax. Multiple extras can be combined with commas, e.g. `pip install 'agent-guardian[full,aws]'`.

| Extra        | What it adds                                                                  | Install when…                                                          |
|--------------|-------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `full`       | WeasyPrint (signed PDF reports), FAISS + sentence-transformers (semantic recall), Presidio (PII detection) | You want PDF output or richer semantic features.                       |
| `pdf-fallback` | ReportLab (lighter PDF engine)                                              | You want PDF but can't install WeasyPrint's native deps.               |
| `aws`        | `botocore` for AWS SigV4 + credential resolution                              | You're using `--model bedrock:<id>`. See [AWS Bedrock](../providers/bedrock.md). |
| `examples`   | LangGraph, LangChain, OpenAI Agents SDK                                       | You want to run the demo target agents in `examples/`.                 |
| `docs`       | MkDocs Material + mkdocstrings                                                | You're building this documentation site locally.                       |
| `dev`        | pytest, ruff, mypy, hypothesis, pre-commit, respx, python-dotenv              | You're contributing to the project.                                    |

## Install from source

```bash
git clone https://github.com/glacien-technologies/agent-guardian.git
cd agent-guardian
pip install -e ".[dev]"
```

This is the usual developer setup — see [Contributing](../contributing.md) for the full local-dev workflow (linting, type-checking, pre-commit hooks).

## Docker

A small image is published under `ghcr.io/glacien-technologies/agent-guardian`. The image ships the base install plus the `[full]` extra so PDF reports work out of the box.

```bash
docker run --rm -it \
  -e OPENAI_API_KEY \
  -v "$PWD":/work -w /work \
  ghcr.io/glacien-technologies/agent-guardian:latest \
  scan --system-prompt prompt.txt --model openai:gpt-4o
```

## What next

- [Quickstart](../quickstart.md) — five-minute end-to-end demo.
- [Your first scan](first-scan.md) — guided walk-through with `--model stub` (no API key required).
- [LLM Providers](../providers/index.md) — wire up OpenAI, Anthropic, Gemini, Bedrock, or local Ollama.
