# AgentGuardian

Adversarial-swarm framework for agentic AI red-teaming.

[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/glacien-technologies/agent-guardian/blob/main/LICENSE)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)

## What it does

Eleven specialist agents attack your AI agent in parallel, coordinated by a
Swarm Commander LLM and shared vector memory. Output: a deterministic 0–100
**AIVSS score** aligned with OWASP Top 10 for Agentic Applications 2026,
MITRE ATLAS v5.4.0, and the CSA Agentic AI Red Teaming Guide.

## At a glance

- Eleven specialist agents — one reconnaissance, ten ASI-aligned attackers.
- Deterministic AIVSS score 0–100 with band, colour, and per-ASI breakdown.
- Four target input modes: system prompt, agent code, HTTP endpoint, framework
  adapter (LangGraph, CrewAI, AutoGen, LlamaIndex, AG2, Semantic Kernel).
- Local live dashboard at `localhost:7474`.
- Signed PDF, JSON, SARIF, and JUnit reports (Ed25519 + HMAC-SHA256).
- Apache-2.0. No telemetry. No API-key requirement (`--model stub`).

## Get started

```bash
pip install agent-guardian
agent-guardian doctor
```

See the [Quickstart](quickstart.md) for the five-minute demo, or jump straight
to the [Architecture](architecture.md) page if you want the technical tour.

## Standards alignment

| Framework                            | Coverage                                                 |
|--------------------------------------|----------------------------------------------------------|
| OWASP Top 10 for Agentic Apps 2026   | All ten ASI categories, one specialist agent each        |
| OWASP AIVSS v0.8                     | Deterministic 0–100 score, four-tier severity bands      |
| MITRE ATLAS v5.4.0                   | Every finding tagged with one or more ATLAS tactic IDs   |
| CSA Agentic AI Red Teaming Guide     | Cross-tagged on every finding                            |

## License

Apache License 2.0. AgentGuardian is a trademark of Glacien Pte. Ltd.
