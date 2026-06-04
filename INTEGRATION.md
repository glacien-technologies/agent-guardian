# Integrating AgentGuardian

AgentGuardian ships three distribution channels and two integration shims. Use the table to pick the right one for your environment.

| Channel | What you get | Best for |
|---------|--------------|----------|
| **PyPI wheel** (`pip install agent-guardian`) | The CLI + Python SDK. | Local dev, custom CI runners, notebook use. |
| **Docker image** (`ghcr.io/glacien-technologies/agent-guardian:latest`) | Pre-built multi-arch image with the CLI as entrypoint. | Air-gapped runners, hermetic CI, one-shot `docker run`. |
| **GitHub Action** (`.github/actions/agentguardian-scan`) | Composite action that installs the wheel, runs `scan`, uploads SARIF, and posts a sticky PR comment. | Any GitHub Actions workflow. |
| **CI templates** (`examples/ci/{github,gitlab,bitbucket}/`) | Copy-pasteable workflow / pipeline files for all three forges. | Dropping AgentGuardian into GitHub Actions, GitLab CI, or Bitbucket Pipelines. |
| **Pre-commit hook** (`.pre-commit-hooks.yaml`) | Local pre-commit entries for `scan` and `doctor`. | Catching regressions before the commit lands. |
| **SARIF 2.1.0** (`--output sarif`) | Standard schema consumed by GitHub Code Scanning, Sonar, DefectDojo, Sarif Web Viewer. | Wiring findings into the security tooling you already run. |

AgentGuardian is a merge gate on all three major forges — **GitHub Actions**, **GitLab CI**, and **Bitbucket Pipelines** — driven by one CLI. Each forge gets a SARIF / Code Quality report, inline annotations, and a single sticky PR/MR comment (upserted in place on every push). The full, consolidated CI/CD documentation lives under [`docs/ci-cd/`](docs/ci-cd/overview.mdx) — start with the [overview](docs/ci-cd/overview.mdx), then the per-forge pages: [GitHub Actions](docs/ci-cd/github-actions.mdx), [GitLab CI](docs/ci-cd/gitlab-ci.mdx), [Bitbucket](docs/ci-cd/bitbucket.mdx). See also [security gates](docs/ci-cd/security-gates.mdx) (the `--fail-under` / `--max-*` flags) and [PR comments](docs/ci-cd/pr-comments.mdx).

> **Stateless gate, no baseline.** The OSS gate judges every scan on its own — it has no memory of a prior scan, so a pre-existing finding can fail the gate and every finding counts. Baseline-diff (failing only on findings a PR *introduces*) is a hosted (SaaS) feature. See the [CI/CD overview](docs/ci-cd/overview.mdx).

## GitHub Actions

Pin the composite action by tag and supply `security-events: write` (SARIF upload) and `pull-requests: write` (sticky comment) on the calling workflow:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glacien-technologies/agent-guardian/.github/actions/agentguardian-scan@v1
        with:
          endpoint: https://my-agent.example.com/chat
          model: gemini:gemini-2.5-flash
          fail-under: "70"
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          AGENT_GUARDIAN_AUTH_BEARER: ${{ secrets.MY_AGENT_BEARER }}
```

Full input reference: [`.github/actions/agentguardian-scan/README.md`](.github/actions/agentguardian-scan/README.md).

## Docker

```bash
docker run --rm \
  -e GEMINI_API_KEY \
  ghcr.io/glacien-technologies/agent-guardian:latest \
  scan --endpoint https://my-agent.example.com/chat \
       --model gemini:gemini-2.5-flash \
       --output sarif --output-path /tmp/scan.sarif
```

The image entrypoint is `agent-guardian`, so any CLI sub-command is reachable. For PDF rendering the image already includes the WeasyPrint native deps.

## Pre-commit

Add the hook repo to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/glacien-technologies/agent-guardian
    rev: v1.0.0
    hooks:
      - id: agentguardian-scan-prompt
        files: ^prompts/.*\.txt$
        args:
          - scan
          - --system-prompt
          - prompts/system.txt
          - --model
          - stub
          - --mode
          - fast
          - --output
          - sarif
          - --output-path
          - .agentguardian/pre-commit.sarif
```

The default hook runs with `--model stub` so no provider key is required. Override `args:` to point at a real model when you want a meaningful pre-commit gate.

## SARIF upload

The composite action uploads SARIF for you. If you run the CLI directly, mirror the upload step:

```yaml
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
    category: agentguardian
```

A static example of what the report looks like, pre-rendered from real scan output: [`docs/_assets/sample-report.html`](docs/_assets/sample-report.html).

## Exit codes

The CLI uses six exit codes — `0` (pass), `1` (gate failed or non-authoritative scan), `2` (config), `3` (target unreachable), `4` (LLM provider), `5` (sandbox), `130` (user interrupt). Full reference: [`docs/reference/exit-codes.mdx`](docs/reference/exit-codes.mdx).
