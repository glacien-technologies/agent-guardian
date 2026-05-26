# AgentGuardian Open

[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)

> The first open-source adversarial-swarm framework for agentic AI red-teaming. Eleven specialist agents attack your AI agent in parallel under a Swarm Commander LLM. Output: a deterministic 0–100 **AIVSS score** aligned with the OWASP Top 10 for Agentic Applications 2026.

## What it does

Single-chain red-teaming tools (PyRIT, garak, Promptfoo, Inspect, DeepTeam) send one prompt at a time. Production agents compose tools, hold memory, and talk to other agents — and that surface needs eleven attackers working in concert.

AgentGuardian deploys a **swarm**: a reconnaissance agent maps your target, then ten specialist agents (one per OWASP ASI category) attack concurrently, coordinated by a Swarm Commander that re-tasks idle agents and stops early on convergence. Every finding is triple-tagged with OWASP ASI, MITRE ATLAS, and CSA Agentic-RT categories.

## Quickstart

```bash
pip install agent-guardian
export OPENAI_API_KEY=sk-...
agent-guardian scan --system-prompt prompt.txt
agent-guardian serve  # live dashboard at http://localhost:7474
```

(Full command set lands at v1.0. Currently in active development.)

## Status

Active development, pre-1.0. See the [PRD](https://github.com/glacien-technologies/agent-guardian) and the milestone-tracking issues for what ships when.

## Why we built this

The agentic-security category will standardise on whichever 0–100 score is published openly first. We want that score to be AIVSS, aligned with the OWASP AIVSS v0.8 working group, so production teams have one number they can track over time and one open framework that maps cleanly to OWASP ASI, MITRE ATLAS, and CSA Agentic-RT categories.

## Contributing

We welcome probes, adapters, bug reports, and PRs. See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a [DCO sign-off](https://developercertificate.org/).

## Security

See [SECURITY.md](SECURITY.md) for responsible-disclosure policy.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Trademark

"AgentGuardian" is a trademark of Glacien Pte. Ltd. See [TRADEMARKS.md](TRADEMARKS.md).
