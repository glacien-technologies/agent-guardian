# AgentGuardian

[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/glacien-technologies/agent-guardian/branch/main/graph/badge.svg)](https://codecov.io/gh/glacien-technologies/agent-guardian)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/glacien-technologies/agent-guardian/badge)](https://scorecard.dev/viewer/?uri=github.com/glacien-technologies/agent-guardian)
[![Downloads](https://static.pepy.tech/badge/agent-guardian/month)](https://pepy.tech/project/agent-guardian)
[![Docs](https://img.shields.io/badge/docs-GitHub-blue.svg)](https://github.com/glacien-technologies/agent-guardian/tree/main/docs)

<!--
README badge row tracks Engineering Standards §11.1.

  * OpenSSF Best Practices and Discord badges were removed pre-launch because
    they pointed at placeholder IDs (``/projects/0000`` and an all-zero server
    ID). They will be added back once the badge URLs resolve — registering at
    https://www.bestpractices.dev (Standard §4.2) and provisioning the Discord
    server (Standard §6.7) are tracked in docs/operator-checklist.md. Shipping
    broken badges to PyPI hurts trust more than missing badges do.
  * The Docs badge points at the GitHub-rendered docs tree until the
    ``agentguardian.ai`` apex DNS lands; the Cloud Run mirror at
    ``agent-guardian-web-u6tm6gzysq-uc.a.run.app/docs`` is the canonical host
    today and the GitHub link is a stable fallback PyPI can resolve forever.

The Scorecard badge will populate once .github/workflows/scorecard.yml runs
its first weekly cron (Sundays 02:00 UTC).
-->


> Open-source multi-agent swarm framework for agentic AI red-teaming
> with deterministic AIVSS scoring aligned to OWASP ASI, MITRE ATLAS,
> and the CSA Agentic AI Red Teaming Guide. Eleven specialist agents
> attack your AI agent in parallel under a Swarm Commander LLM. Output:
> a deterministic 0–100 **AIVSS score** aligned with the OWASP Top 10
> for Agentic Applications 2026, MITRE ATLAS v5.4.0, and the CSA
> Agentic AI Red Teaming Guide.

## Why

Single-chain red-teaming tools send one prompt at a time. Production
agents compose tools, hold memory, talk to other agents, and run real
code — and that surface needs eleven attackers working in concert.

AgentGuardian deploys a **swarm**: a reconnaissance agent maps your
target, then ten specialist agents (one per OWASP ASI category) attack
concurrently, coordinated by a Swarm Commander that re-tasks idle agents
and stops early on convergence. Every finding is triple-tagged with
OWASP ASI, MITRE ATLAS, and CSA Agentic-RT categories.

Read the full rationale: [Why we built this](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/why.md).

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

Full walkthrough: [Five-minute quickstart](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/quickstart.md).

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
an AIVSS threshold. See [`docs/concepts/scan-modes.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/concepts/scan-modes.md)
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

Full architecture: [docs/architecture](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/architecture.md).

## Status

**v1.0.0 — Generally Available.** Production/Stable on PyPI. The eleven-agent
swarm, the deterministic AIVSS scorer, the live dashboard, and the
Sigstore-signed evidence pipeline are all production-ready. Active development
continues on the v1.1 stream (see CHANGELOG and roadmap).

Roadmap: [docs/roadmap](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/roadmap.md).

## Documentation

- [Why we built this](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/why.md)
- [Quickstart](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/quickstart.md)
- [Architecture](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/architecture.md)
- [AIVSS formula](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/aivss-formula.md)
- [Adapters](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/adapters/index.md)
- [API reference](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/api/index.md)
- [Ethics and responsible use](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/ethics.md)
- [Roadmap](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/roadmap.md)

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
these terms. See [Ethics](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/ethics.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Trademark

"AgentGuardian" is a trademark of Glacien Pte. Ltd. See
[TRADEMARKS.md](TRADEMARKS.md).
