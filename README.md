# AgentGuardian

[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/glacien-technologies/agent-guardian/branch/main/graph/badge.svg)](https://codecov.io/gh/glacien-technologies/agent-guardian)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/glacien-technologies/agent-guardian/badge)](https://scorecard.dev/viewer/?uri=github.com/glacien-technologies/agent-guardian)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/0000/badge)](https://www.bestpractices.dev/projects/0000)
[![Downloads](https://static.pepy.tech/badge/agent-guardian/month)](https://pepy.tech/project/agent-guardian)
[![Discord](https://img.shields.io/discord/0000000000000000?label=discord&logo=discord)](https://discord.gg/agentguardian)
[![Docs](https://img.shields.io/badge/docs-agentguardian.ai-cyan.svg)](https://glacien-technologies.github.io/agent-guardian/)

<!--
README badge row tracks Engineering Standards §11.1. Two badges currently
point at placeholder IDs that need replacement after the manual setup:

  * OpenSSF Best Practices — replace ``/projects/0000`` after registering
    at https://www.bestpractices.dev (Standard §4.2). The form takes ~2 hr.
  * Discord — replace the all-zero server ID once the Discord server is
    provisioned (Standard §6.7). The invite URL ``discord.gg/agentguardian``
    is the canonical alias to set up.

The Scorecard badge will populate once .github/workflows/scorecard.yml runs
its first weekly cron (Sundays 02:00 UTC).
-->


> The first open-source adversarial-swarm framework for agentic AI
> red-teaming. Eleven specialist agents attack your AI agent in parallel
> under a Swarm Commander LLM. Output: a deterministic 0–100 **AIVSS
> score** aligned with the OWASP Top 10 for Agentic Applications 2026,
> MITRE ATLAS v5.4.0, and the CSA Agentic AI Red Teaming Guide.

## Why

Single-chain red-teaming tools send one prompt at a time. Production
agents compose tools, hold memory, talk to other agents, and run real
code — and that surface needs eleven attackers working in concert.

AgentGuardian deploys a **swarm**: a reconnaissance agent maps your
target, then ten specialist agents (one per OWASP ASI category) attack
concurrently, coordinated by a Swarm Commander that re-tasks idle agents
and stops early on convergence. Every finding is triple-tagged with
OWASP ASI, MITRE ATLAS, and CSA Agentic-RT categories.

Read the full rationale: [Why we built this](https://glacien-technologies.github.io/agent-guardian/why/).

## How it compares

| Tool             | Multi-agent swarm | Agentic-AI focus | Standards alignment             | Open formula | License     |
|------------------|:-----------------:|:----------------:|---------------------------------|:------------:|-------------|
| PyRIT            |        no         |        no        | NIST AI RMF (partial)           |    no        | MIT         |
| garak            |        no         |        no        | own taxonomy                    |    no        | Apache-2.0  |
| Promptfoo        |        no         |        no        | own taxonomy                    |    no        | MIT         |
| Inspect          |        no         |        no        | own taxonomy                    |    no        | MIT         |
| DeepTeam         |        no         |        no        | OWASP LLM Top 10                |    no        | Apache-2.0  |
| **AgentGuardian** |     **yes**       |    **yes**       | **OWASP ASI + ATLAS + CSA + AIVSS** | **yes**   | **Apache-2.0** |

## Quickstart

```bash
pip install agent-guardian

# Pick an LLM backend, or use --model stub for zero-key testing.
export OPENAI_API_KEY=sk-...

# Scan a system prompt
echo "You are a helpful customer-support bot." > prompt.txt
agent-guardian scan --system-prompt prompt.txt

# Live dashboard at http://localhost:7474
agent-guardian serve

# Marketing badge
agent-guardian badge $(agent-guardian last-score) --svg > badge.svg
```

Full walkthrough: [Five-minute quickstart](https://glacien-technologies.github.io/agent-guardian/quickstart/).

## Run with Docker

```bash
docker build -t agent-guardian:dev .
docker run --rm -p 7474:7474 agent-guardian:dev serve --host 0.0.0.0
```

Or with the bundled compose file:

```bash
docker compose up --build
```

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

Full architecture: [docs/architecture](https://glacien-technologies.github.io/agent-guardian/architecture/).

## Status

Active development, pre-1.0. The swarm, the scorer, the dashboard, and
the signed-report pipeline are all in place. v1.0 ships on PyPI at M15.

Roadmap: [docs/roadmap](https://glacien-technologies.github.io/agent-guardian/roadmap/).

## Documentation

- [Why we built this](https://glacien-technologies.github.io/agent-guardian/why/)
- [Quickstart](https://glacien-technologies.github.io/agent-guardian/quickstart/)
- [Architecture](https://glacien-technologies.github.io/agent-guardian/architecture/)
- [AIVSS formula](https://glacien-technologies.github.io/agent-guardian/aivss-formula/)
- [Adapters](https://glacien-technologies.github.io/agent-guardian/adapters/)
- [API reference](https://glacien-technologies.github.io/agent-guardian/api-reference/)
- [Ethics and responsible use](https://glacien-technologies.github.io/agent-guardian/ethics/)
- [Roadmap](https://glacien-technologies.github.io/agent-guardian/roadmap/)

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
these terms. See [Ethics](https://glacien-technologies.github.io/agent-guardian/ethics/).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Trademark

"AgentGuardian" is a trademark of Glacien Pte. Ltd. See
[TRADEMARKS.md](TRADEMARKS.md).
