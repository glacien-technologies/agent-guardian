<div align="center">

# AgentGuardian

**Red-team your AI agents before attackers do.**

[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/glacien-technologies/agent-guardian/badge)](https://api.securityscorecards.dev/projects/github.com/glacien-technologies/agent-guardian)
<!-- OpenSSF Best Practices badge — PLACEHOLDER.
     Register the project at https://www.bestpractices.dev/ , then replace
     <ID> below with the issued numeric project id and uncomment the line.
     Criteria evidence is mapped in docs/security/openssf-badge-status.md. -->
<!-- [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>) -->
[![Docs](https://img.shields.io/badge/docs-docs.agentguardian.io-1f6feb.svg)](https://docs.agentguardian.io)

[Docs](https://docs.agentguardian.io) · [Quickstart](https://docs.agentguardian.io/quickstart) · [Try the demo agent](https://docs.agentguardian.io/start-here/try-the-demo-agent) · [Attack library](https://docs.agentguardian.io/attacks/overview) · [CI/CD](https://docs.agentguardian.io/ci-cd/overview) · [Sample report](./docs/_assets/sample-report.pdf)

</div>

---

AgentGuardian is an open-source red-teaming toolkit for AI agents. It scans your agent, maps the attack surface, runs the relevant adversarial agents, and generates evidence-backed findings for you to review — and fix the vulnerabilities before they reach production.

<p align="center">
  <img src="./docs/images/swarm-diagrams/agentguardian-security-loop.jpg" alt="AgentGuardian recon, OWASP ASI probe generation, findings, reports, and fix-rerun loop" width="900">
</p>

<p align="center">▶ <b><a href="https://youtu.be/AD-CIIccklA">Watch the demo</a></b> to see how AgentGuardian finds vulnerabilities in a live scan.</p>

## Getting started

**1. Install**

```bash
pip install agent-guardian
```

or

```bash
uv tool install agent-guardian
```

**2. Configure a model provider**

AgentGuardian drives its attacks with an LLM. Export a key for your provider — Gemini, OpenAI, or Anthropic:

```bash
export GEMINI_API_KEY=...        # or OPENAI_API_KEY / ANTHROPIC_API_KEY
```

For every supported provider and the full set of configuration options, see the [configuration guide](https://docs.agentguardian.io/reference/config#provider-api-keys).

**3. Scan an agent**

No agent of your own yet? Point it at the hosted demo target — a deliberately vulnerable "finbot" banking agent:

```bash
agent-guardian scan \
  --endpoint https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app/finbot/chat \
  --model gemini:gemini-3.5-flash \
  --mode fast \
  --output pdf --output-path report.pdf
```

To scan **your own** agent instead, swap `--endpoint` for any target — a hosted URL or a `--system-prompt` file (see [What you can scan](#what-you-can-scan)).

**4. Review the findings**

AgentGuardian opens a live dashboard while it runs (`http://127.0.0.1:7474`) and writes an evidence bundle — findings, transcripts, and your PDF report — under `~/.agentguardian/scans/<scan-id>/`.

## What you can scan

### Scan an HTTP agent

```bash
agent-guardian scan \
  --endpoint http://localhost:8000/chat \
  --model gemini:gemini-3.5-flash \
  --mode smart
```

### Scan a system prompt

```bash
agent-guardian scan \
  --system-prompt ./prompts/customer-support-agent.txt \
  --model gemini:gemini-3.5-flash \
  --mode fast
```

### Scan an in-process agent

```bash
agent-guardian scan my_app.agent:agent \
  --model gemini:gemini-3.5-flash \
  --mode smart
```

Point AgentGuardian at any importable Python callable or agent object (`module:attr`) and it runs in-process — useful for pre-deploy and CI, with nothing to host.

> **Roadmap — white-box agentic detection.** Today's scans are **black-box**: AgentGuardian drives the agent adversarially and detects compromise from what is observable (the response, returned data, and any tool calls the API exposes) across the full OWASP ASI taxonomy. Framework-native modes (LangGraph, CrewAI, AutoGen, OpenAI Agents, ADK, Strands) and OpenTelemetry trace correlation are in progress — they will read the agent's own tool/sub-agent traces to catch internal tool-misuse a clean reply can hide. Follow [#126](https://github.com/glacien-technologies/agent-guardian/issues/126).

## What AgentGuardian catches

AgentGuardian tests agentic risks that normal prompt scanners miss:

- Prompt injection and goal hijack
- Unsafe tool calls and tool chaining
- Privilege abuse
- RAG poisoning and indirect prompt injection
- Memory and context poisoning
- Sensitive data leakage
- Agent-to-agent manipulation
- Cascading failures
- Trust exploitation and unsafe outputs
- Goal drift and untraceable behavior

## Reports and evidence

Every scan writes a local evidence bundle under `~/.agentguardian/scans/<scan-id>/`:

- `scan.json` — machine-readable findings, signed (HMAC-SHA256 + Ed25519)
- `events.jsonl` — the scan timeline
- `probe/` — per-probe requests, responses, verdicts, and evidence
- `forensic_manifest.json` — integrity manifest for the bundle
- a live local dashboard — browse findings, transcripts, and exports

Generate shareable or CI-ready reports in any format on demand:

```bash
agent-guardian report SCAN_ID --output sarif --output-path scan.sarif   # GitHub Security
agent-guardian report SCAN_ID --output md                                # Markdown
agent-guardian report SCAN_ID --output pdf  --output-path report.pdf      # shareable PDF
```

Formats: `json` · `sarif` · `junit` · `md` · `gitlab` · `pdf`. Stored evidence can be verified with `agent-guardian verify`.

## How it works

Every scan follows the same loop:

```text
Target → surface mapping → adversarial agents → AIVSS-scored findings → evidence bundle
```

For the full workflow, see [how AgentGuardian works](https://docs.agentguardian.io/concepts/target-adapters).

## Scan modes

- `fast` — quick local feedback
- `smart` — broader coverage for development and pull requests
- `full` — release gates and audit evidence

Use `full` when you need AIVSS-scored findings for CI/CD gates.

## Commands

| Command | What it does |
| --- | --- |
| `agent-guardian scan` | Run an adversarial swarm scan against a target |
| `agent-guardian report <id> --output FMT` | Regenerate a report — `json` · `sarif` · `junit` · `md` · `gitlab` · `pdf` · `badge` |
| `agent-guardian gate <id> --fail-under N` | Apply pass/fail thresholds to a stored scan (CI exit codes) |
| `agent-guardian serve` | Start the local dashboard |
| `agent-guardian scans list` / `delete` | List or delete stored scans (`delete --older-than 30d` for bulk cleanup) |
| `agent-guardian config show` / `init` | Inspect the effective config / scaffold a config file |
| `agent-guardian verify <report>` | Verify the HMAC-SHA256 + Ed25519 signatures on a report |
| `agent-guardian last-score` | Print the AIVSS of the most recent scan |
| `agent-guardian doctor` | Verify the install, provider keys, and prerequisites |
| `agent-guardian telemetry status` | Manage opt-in telemetry (`enable` / `disable`) |
| `agent-guardian version` | Print the installed version |

Run any command with `--help` for its full options, or see the [CLI reference](https://docs.agentguardian.io/reference/cli).

## CI/CD with GitHub Actions

The shipped composite action runs a scan, uploads SARIF to GitHub Code Scanning, and (optionally) posts a summary comment on the pull request:

```yaml
name: AgentGuardian

on:
  pull_request:
  push:
    branches: [main]

jobs:
  red-team:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload SARIF to Code Scanning
      pull-requests: write     # post the summary comment
    steps:
      - uses: actions/checkout@v4

      - uses: glacien-technologies/agent-guardian/.github/actions/agentguardian-scan@v1
        with:
          endpoint: http://localhost:8000/chat
          model: gemini:gemini-3.5-flash
          mode: full
          fail-under: "80"
          max-critical: "0"
          comment: "true"
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

The job fails when the gate (`fail-under` / `max-critical`) is breached. For GitLab, Bitbucket, raw-CLI, and fleet/nightly setups, see the [CI/CD guides](https://docs.agentguardian.io/ci-cd/overview) — including the [parallel suites guide](https://docs.agentguardian.io/ci-cd/parallel-suites) for scanning many agents from one file.

## Standards and coverage

AgentGuardian maps its shipped probes to:

- OWASP Top 10 for Agentic Applications
- MITRE ATLAS
- CSA Agentic AI Red Teaming Guide

The exact agents and probes that ran against your target are enumerated in every scan report (`coverage` in `scan.json`). The full probe-to-standard mapping lives in the [OWASP mapping](https://docs.agentguardian.io/reports/owasp-mapping) and the [framework coverage matrix](https://docs.agentguardian.io/reference/framework-coverage-matrix).

## Privacy & telemetry

**Telemetry is opt-in and disabled by default.** Out of the box AgentGuardian sends nothing — no analytics ping, no install ping, no scan counts. Telemetry only activates after you explicitly opt in. Once enabled, it sends anonymous operational counts (agents dispatched, attempts, findings) plus a locally generated, anonymous install id (a random UUID stored at `~/.agentguardian/install_id`, with no link to your identity).

Manage it any time:

```bash
agent-guardian telemetry status     # show current state
agent-guardian telemetry enable      # opt in
agent-guardian telemetry disable     # opt out
```

AgentGuardian never collects prompts, agent responses, target URLs, headers, secrets, API keys, transcripts, reports, evidence files, tool inputs or outputs, or customer data.

## Run from source

To run AgentGuardian from a source checkout instead of the published package:

```bash
# clone
git clone https://github.com/glacien-technologies/agent-guardian.git
cd agent-guardian

# virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# install the checkout in editable mode
pip install -e ".[dev]"

# run it from source
agent-guardian doctor
agent-guardian scan \
  --endpoint http://localhost:8000/chat \
  --model gemini:gemini-3.5-flash \
  --mode fast
```

For contribution guidelines, see the [contribution guide](https://docs.agentguardian.io/community/contributing).

## Contributing

We welcome new probes, new adapters, and new attacker logic. Start with the [contribution guide](https://docs.agentguardian.io/community/contributing) and the [`good first issue`](https://github.com/glacien-technologies/agent-guardian/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label.

All commits must be DCO-signed:

```bash
git commit -s
```

By participating you agree to [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) and the [ethics policy](https://docs.agentguardian.io/community/ethics). AgentGuardian is for testing systems you own or are explicitly authorised to test.

## Community

Join us on [Discord](https://discord.gg/X6UFKYXdBJ) for quickstart help, probe design, adapter questions, and roadmap discussion. For longer-form support channels, see the [support guide](https://docs.agentguardian.io/community/support).

## Security

To report a vulnerability, see [`SECURITY.md`](./SECURITY.md). Do **not** open public issues for security reports.

## License

Apache-2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

`AgentGuardian` is a trademark of Glacien Technologies. See [`TRADEMARKS.md`](./TRADEMARKS.md) for usage guidelines.
