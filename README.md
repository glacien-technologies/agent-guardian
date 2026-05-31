# AgentGuardian

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![No telemetry](https://img.shields.io/badge/telemetry-none-brightgreen.svg)](#what-agentguardian-open-is-not)
[![Local-first](https://img.shields.io/badge/local--first-yes-brightgreen.svg)](#what-agentguardian-open-is-not)
[![Docker](https://img.shields.io/badge/docker-available-2496ED.svg?logo=docker)](Dockerfile)
[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![GitHub Actions](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF.svg?logo=githubactions)](.github/workflows/ci.yml)
[![SARIF export](https://img.shields.io/badge/SARIF-export-purple.svg)](https://agentguardian.io/reports/sarif-export)
[![OWASP ASI](https://img.shields.io/badge/OWASP-ASI%202026-orange.svg)](https://owasp.org/www-project-top-10-for-agentic-applications/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/glacien-technologies/agent-guardian/branch/main/graph/badge.svg)](https://codecov.io/gh/glacien-technologies/agent-guardian)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/glacien-technologies/agent-guardian/badge)](https://scorecard.dev/viewer/?uri=github.com/glacien-technologies/agent-guardian)
[![Downloads](https://static.pepy.tech/badge/agent-guardian/month)](https://pepy.tech/project/agent-guardian)
[![Docs](https://img.shields.io/badge/docs-agentguardian.io-blue.svg)](https://agentguardian.io)
[![Project Status: Active](https://img.shields.io/badge/Project_Status-Active-brightgreen.svg)](https://agentguardian.io/community/release-cadence)
[![Release cadence: weekly](https://img.shields.io/badge/Release_Cadence-Weekly_(90d)-blue.svg)](https://agentguardian.io/community/release-cadence)

> **Status:** Active · v1.0.0 (Stable on PyPI) · See [CHANGELOG](CHANGELOG.md) and [ROADMAP](https://agentguardian.io/community/roadmap).

**Red team your AI agents before attackers do — find prompt injection, tool abuse, RAG poisoning, memory attacks, and unsafe agent behavior in 5 minutes.**

<p align="center">
  <img src="docs/_assets/demo-scan.gif" alt="AgentGuardian scanning a local agent and rendering findings in the live dashboard" width="820">
  <br>
  <sub>30-second demo: <code>agent-guardian scan</code> against a local agent, findings rendered live at <code>http://localhost:7474</code>.</sub>
</p>

AgentGuardian is an open-source, local-first, Apache-2.0 licensed
red-teaming toolkit for AI agents. Point it at your LangGraph, CrewAI,
MCP server, RAG app, or REST-API agent — it deploys a swarm of 14
specialist attackers against it under a Swarm Commander LLM, produces a
deterministic 0–100 **AIVSS score** mapped to OWASP ASI 2026,
MITRE ATLAS v5.4.0, and the CSA Agentic AI Red Teaming Guide, and
emits SARIF / JSON / JUnit / Markdown / PDF reports your CI can gate on.

**Supported targets:** LangGraph · CrewAI · OpenAI Agents SDK · MCP servers · A2A endpoints · any HTTP/REST agent · raw system prompts.

**Reports:** SARIF (for GitHub Security tab) · JSON · JUnit · Markdown · PDF · HTML ([sample](docs/_assets/sample-scan-report.html)).

```bash
pip install agent-guardian

# Run a 5-minute scan against your own agent (no API key required for stub mode)
echo "You are a helpful customer-support bot." > prompt.txt
agent-guardian scan --system-prompt prompt.txt --model stub --mode fast
```

Full docs: **[agentguardian.io](https://agentguardian.io)** ·
Quickstart: **[agentguardian.io/quickstart](https://agentguardian.io/quickstart)** ·
Press kit: **[gtm/press-kit](gtm/press-kit/)**

---

<!--
README badge row tracks Engineering Standards §11.1.

  * OpenSSF Best Practices and Discord badges were removed pre-launch because
    they pointed at placeholder IDs (``/projects/0000`` and an all-zero server
    ID). They will be added back once the badge URLs resolve — registering at
    https://www.bestpractices.dev (Standard §4.2) and provisioning the Discord
    server (Standard §6.7) are tracked in docs/operator-checklist.md. Shipping
    broken badges to PyPI hurts trust more than missing badges do.

The Scorecard badge will populate once .github/workflows/scorecard.yml runs
its first weekly cron (Sundays 02:00 UTC).
-->

## Why

Single-chain red-teaming tools send one prompt at a time. Production
agents compose tools, hold memory, talk to other agents, and run real
code — and that surface needs fourteen attackers working in concert.

AgentGuardian deploys a **swarm**: a reconnaissance agent maps your
target, then specialist agents (one per OWASP ASI category, plus the
A2A and cascading-failure attackers) attack concurrently, coordinated
by a Swarm Commander that re-tasks idle agents and stops early on
convergence. Every finding is triple-tagged with OWASP ASI, MITRE
ATLAS, and CSA Agentic-RT categories.

Read the full rationale: [Why we built this](https://agentguardian.io/concepts/how-agentguardian-works).

## How it compares

| Tool             | Multi-agent swarm | Agentic-AI focus | Standards alignment                          | Open formula | License     |
|------------------|:-----------------:|:----------------:|----------------------------------------------|:------------:|-------------|
| PyRIT [¹](#fn1)  |        no         |        no        | NIST AI RMF (partial)                        |    no        | MIT         |
| garak            |        no         |        no        | own taxonomy                                 |    no        | Apache-2.0  |
| Promptfoo        |        no         |        no        | OWASP LLM Top 10 + ATLAS + EU AI Act [²](#fn2) |    no        | MIT         |
| Inspect          |        no         |        no        | own taxonomy                                 |    no        | MIT         |
| DeepTeam         |        no         |        no        | OWASP LLM Top 10                             |    no        | Apache-2.0  |
| **AgentGuardian** |     **yes**       |    **yes**       | **OWASP ASI + ATLAS + CSA + AIVSS**          |    **yes**   | **Apache-2.0** |

<a name="fn1">¹</a> Microsoft's public PyRIT repository at `Azure/PyRIT` was archived
2026-03-27 and is no longer maintained. We keep PyRIT in the comparison because it
remains the academic reference most readers know; new work should consider one of
the maintained alternatives instead.

<a name="fn2">²</a> Promptfoo's red-team product (`promptfoo redteam`) ships plugin
packs that map to OWASP LLM Top 10, MITRE ATLAS, and the EU AI Act risk taxonomy.
The "own taxonomy" wording that appeared here in earlier drafts referred to
Promptfoo's eval framework, not its red-team product — corrected for accuracy.

## What it tests — 10 OWASP ASI 2026 categories, 96 probes

| ASI    | Category                | Probes | What it covers                                                                 |
|--------|-------------------------|:------:|--------------------------------------------------------------------------------|
| ASI01  | Goal Hijack             |   9    | Direct / indirect prompt injection, role-swap, EchoLeak zero-click, persona-break jailbreak. |
| ASI02  | Tool Misuse             |   8    | Argument injection, chain exfiltration, scope expansion, recursion bombs.       |
| ASI03  | Privilege Abuse         |   9    | Cross-tenant reads, JIT credential bypass, role inheritance, scope-token replay. |
| ASI04  | Supply Chain            |   8    | MCP server poisoning, registry spoofing, plugin hijack, poisoned fine-tunes.    |
| ASI05  | Code Execution          |   8    | Sandbox escape, unsafe pickle, shell meta-injection, lockfile poisoning.        |
| ASI06  | Memory Poisoning        |  13    | RAG corpus inject, persistent triggers, cross-tenant vector bleed, HITL bypass. |
| ASI07  | Agent-to-Agent (A2A)    |   8    | Supervisor impersonation, message-bus spoofing, confused deputy, downgrade.     |
| ASI08  | Cascading Failures      |   8    | Retry storms, alarm suppression, dependency cascade, feedback amplification.    |
| ASI09  | Trust Exploitation      |  17    | Output-reflection XSS, fabricated citations, denial-of-wallet, jailbreaks.      |
| ASI10  | Rogue Agents (drift)    |   8    | Long-horizon drift, mode shift, capability mask, self-replicate via API.        |

**Total: 96 probes**, all triple-tagged with OWASP ASI 2026, MITRE ATLAS v5.4.0, and CSA Agentic-RT categories.
Full catalogue: [agentguardian.io/attacks/overview](https://agentguardian.io/attacks/overview) · enumerate locally with `agent-guardian list-probes`.

## Quickstart

```bash
pip install agent-guardian
# or, for an isolated CLI install:
pipx install agent-guardian

# Pick an LLM backend, or use --model stub for zero-key testing.
export OPENAI_API_KEY=sk-...

# Scan a system prompt
echo "You are a helpful customer-support bot." > prompt.txt
agent-guardian scan --system-prompt prompt.txt

# Live dashboard at http://localhost:7474
agent-guardian serve

# Marketing badge
agent-guardian badge $(agent-guardian last-score --score-only) --svg > badge.svg
```

Full walkthrough: [Five-minute quickstart](https://agentguardian.io/quickstart).

## Run with Docker

```bash
docker build -t agent-guardian:dev .
docker run --rm -p 7474:7474 agent-guardian:dev serve --host 0.0.0.0
```

Or with the bundled compose file:

```bash
docker compose up --build
```

## CI integration

Wire AgentGuardian into your GitHub Actions pipeline as a PR-gate. The
SARIF output uploads straight into GitHub's Security tab via
`codeql-action/upload-sarif`, so findings show up inline on the PR.

```yaml
# .github/workflows/agent-guardian.yml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: { python-version: "3.11" }
- run: pip install agent-guardian
- run: agent-guardian scan my-agent.py --mode fast --output sarif --output-path scan.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: scan.sarif }
```

Pair with `--fail-under <score>` on the scan step to gate the merge on
an AIVSS threshold. See [scan modes](https://agentguardian.io/concepts/how-agentguardian-works)
for per-mode cost / wall-time numbers and recommended thresholds.

## Architecture

```
                          ┌─────────────────────────────┐
                          │     Swarm Commander LLM     │
                          │  (orchestration & dispatch) │
                          └──────────┬──────────────────┘
                                     │
                ┌────────────────────┼────────────────────┐
                │                    │                    │
                ▼                    ▼                    ▼
        ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
        │  Recon Agent │     │   Shared     │     │   Findings   │
        │  (map target)│◀───▶│ Vector Memory│◀───▶│  Aggregator  │
        └──────────────┘     └──────────────┘     └──────────────┘
                                     ▲
                ┌────────────────────┼────────────────────┐
                │   Ten ASI-aligned specialist attackers  │
                │   running in parallel                   │
                │                                         │
                │   ASI01  Goal Hijack                    │
                │   ASI02  Tool Misuse                    │
                │   ASI03  Privilege Abuse                │
                │   ASI04  Supply Chain                   │
                │   ASI05  Unauthorised Code Execution    │
                │   ASI06  Memory Poisoning               │
                │   ASI07  Agent-to-Agent Compromise      │
                │   ASI08  Cascading Failures             │
                │   ASI09  Trust Exploitation             │
                │   ASI10  Rogue Agent / Drift            │
                └─────────────────────────────────────────┘
```

Full architecture: [docs/architecture](https://agentguardian.io/concepts/how-agentguardian-works).

## Status

**v1.0.0 — Generally Available · Active development.** Production/Stable
on PyPI. The multi-agent swarm, the deterministic AIVSS scorer, the live
dashboard, and the Sigstore-signed evidence pipeline are all
production-ready. v1.1 work is tracked in the [CHANGELOG](CHANGELOG.md)
under `[1.1.0] — Unreleased`.

Roadmap: [agentguardian.io/community/roadmap](https://agentguardian.io/community/roadmap) ·
Release cadence and SLAs: see [GOVERNANCE](governance.md).

## What AgentGuardian is NOT

To set expectations honestly — AgentGuardian is a **testing**
toolkit. It is not, and is not trying to be:

- **A runtime gateway.** It does not sit in front of your agent at
  serve time. It does not gate, block, redact, or rewrite production
  traffic.
- **A guardrail product.** It does not enforce policy on a live
  conversation.
- **A policy proxy.** It does not mediate requests between your agent
  and its LLM backend.
- **A managed service.** Reports are written to your local disk. We do
  not host them.
- **A telemetry collector.** AgentGuardian does not phone home
  by design.

If you want runtime governance, managed evidence packs, team workflows,
audit dashboards, or commercial SLA support, those live in
**AgentGuardian Enterprise** from Glacien — see
[agentguardian.io/enterprise](https://agentguardian.io/enterprise).

## Documentation

- [Quickstart](https://agentguardian.io/quickstart) — 5 minutes from
  `pip install` to your first report.
- [How AgentGuardian works](https://agentguardian.io/concepts/how-agentguardian-works)
  — the swarm architecture and scoring model.
- [Attack library](https://agentguardian.io/attacks/overview) —
  every probe and the ASI category it tests.
- [Reports & evidence](https://agentguardian.io/reports/report-overview)
  — output formats and how to read them.
- [CI/CD integration](https://agentguardian.io/ci-cd/github-actions) —
  GitHub Actions, GitLab CI, SARIF upload to GitHub Security.
- [Open vs Enterprise](https://agentguardian.io/concepts/open-vs-enterprise)
  — what's in OSS, what's in Enterprise.
- [Research foundation](https://agentguardian.io/concepts/research-foundation)
  — TAP, MAD-MAX, RedAgent, Co-RedTeam, MUZZLE, MITRE ATLAS, CSA,
  AIVSS — the work this is built on.

## Contributing

We welcome probes, adapters, bug reports, and PRs. See
[CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a
[DCO sign-off](https://developercertificate.org/).

## Security

See [SECURITY.md](SECURITY.md) for responsible-disclosure policy. If you
find a vulnerability in AgentGuardian itself, please email
[security@glacien.ai](mailto:security@glacien.ai) instead of filing a
public issue.

## Ethics

AgentGuardian is for testing systems you own or are explicitly
authorised to test. Use against third-party systems without
authorisation is unlawful in most jurisdictions and a violation of
these terms. See [Ethics](https://agentguardian.io/community/security-policy).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Trademark

"AgentGuardian" is a trademark of Glacien Pte. Ltd. See
[TRADEMARKS.md](TRADEMARKS.md).
