# AgentGuardian scan — GitHub Action

A composite GitHub Action that runs an AgentGuardian adversarial-swarm scan and uploads the SARIF report to GitHub Code Scanning.

## Quick start

```yaml
name: AgentGuardian
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glacien-technologies/agent-guardian/.github/actions/agentguardian-scan@v1
        with:
          framework: langgraph
          framework-ref: my_app.graph:graph
          model: gemini:gemini-2.5-flash
          fail-under: "70"
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `target` | `""` | Positional scan target (`MODULE:ATTR`). Mutually exclusive with the other target inputs. |
| `system-prompt` | `""` | Path to a system prompt file (prompt-only target). |
| `endpoint` | `""` | Hosted HTTP endpoint URL of the target agent. |
| `framework` | `""` | One of `adk`, `autogen`, `crewai`, `langgraph`, `openai_agents`, `strands`. |
| `framework-ref` | `""` | `MODULE:ATTR` dotted reference to the framework-native object. |
| `model` | `stub` | LLM model spec (e.g. `openai:gpt-4o`, `gemini:gemini-2.5-flash`). |
| `mode` | `full` | `fast`, `smart`, or `full`. Only `full` produces an authoritative gate. |
| `budget-usd` | `""` | Runtime USD cap. Empty disables the cap. |
| `fail-under` | `70` | Minimum AIVSS for exit-0. Empty skips the gate. |
| `output-path` | `agentguardian-scan.sarif` | Filesystem path the SARIF is written to. |
| `upload-sarif` | `true` | Skip upload by setting `false` (e.g. if Advanced Security is off). |
| `category` | `agentguardian` | SARIF category used to group runs in Code Scanning. |
| `agent-guardian-version` | `""` | `pip install` version specifier. Empty installs latest. |
| `python-version` | `3.12` | Python runtime version. |
| `extra-args` | `""` | Extra flags appended verbatim to `agent-guardian scan`. |

## Outputs

| Name | Description |
|------|-------------|
| `sarif-path` | Filesystem path of the SARIF report. |
| `exit-code` | Raw `agent-guardian scan` exit code (see [exit codes](../../../docs/reference/exit-codes.mdx)). |

## Required permissions

The calling workflow must grant `security-events: write` for SARIF upload to succeed. Composite actions cannot declare repository-level permissions, so this stays the caller's responsibility.

```yaml
permissions:
  contents: read
  security-events: write
```

## Provider credentials

Set the secret matching the `model` input:

| `model` prefix | Secret |
|----------------|--------|
| `openai:`      | `OPENAI_API_KEY` |
| `anthropic:`   | `ANTHROPIC_API_KEY` |
| `gemini:`      | `GEMINI_API_KEY` |
| `bedrock:`     | AWS credentials via OIDC or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| `ollama:`      | None (assumes a reachable Ollama host) |
| `stub`         | None (offline; always fails `fail-under`) |

Pass the secret through `env:` on the job or step, the action picks it up the same way the CLI does.

## Failure semantics

The action fails the workflow step when `agent-guardian scan` exits non-zero. SARIF upload still runs in that case (it is guarded by `if: always()`), so findings are visible in the **Security → Code scanning** tab even on a gate failure. The mapping between exit codes and gate decisions matches the CLI exactly — see [docs/reference/exit-codes](../../../docs/reference/exit-codes.mdx).

## Versioning

This action is published from the main `agent-guardian` repository at the path `.github/actions/agentguardian-scan`. Pin by tag:

```yaml
uses: glacien-technologies/agent-guardian/.github/actions/agentguardian-scan@v1
```

The `v1` major tag tracks the latest backward-compatible release.
