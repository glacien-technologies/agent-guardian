<div align="center">

# AgentGuardian

**Open-source red-team testing toolkit for agentic AI systems.**

96 attack probes · 11 attacker agents · OWASP ASI 2026 (all 10), 11+ MITRE ATLAS v5.4.0 techniques (see [coverage matrix](./docs/reference/framework-coverage-matrix.md) for the exact set; ~85% of techniques are out of scope for a black-box agent scanner) and CSA Agentic-RT (all 12) mappings · SARIF + PDF reports · runs offline.

[![PyPI](https://img.shields.io/pypi/v/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![Python](https://img.shields.io/pypi/pyversions/agent-guardian.svg)](https://pypi.org/project/agent-guardian/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/glacien-technologies/agent-guardian/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/glacien-technologies/agent-guardian/badge)](https://api.securityscorecards.dev/projects/github.com/glacien-technologies/agent-guardian)
[![Docs](https://img.shields.io/badge/docs-agentguardian.io-1f6feb.svg)](https://agentguardian.io)

</div>

---

## What it is

AgentGuardian is a testing toolkit that runs adversarial probes against your agent — LangGraph, CrewAI, OpenAI Agents SDK, AutoGen, ADK, Strands, or any HTTP endpoint — and produces a signed-style evidence bundle you can hand to security review.

It ships **96 attack probes** organised against three public taxonomies:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/) (ASI01–ASI10, all 10 categories covered)
- [MITRE ATLAS v5.4.0](https://atlas.mitre.org/) (February 2026 release) — **11+ techniques covered** at the agent's I/O surface; the remaining ~85% of the v5.4.0 catalogue (training-pipeline / ML-platform-internal attacks) is out of scope for a black-box agent scanner. See the [framework-coverage matrix](./docs/reference/framework-coverage-matrix.md) for the exact set.
- [CSA Agentic AI Red Teaming Guide](https://cloudsecurityalliance.org/) (Huang et al., 2025-05-28, all 12 categories)

It is deterministic in `stub` mode (no LLM key required), reproducible by seed, and emits SARIF + PDF + HTML + JSON.

---

## Install

```bash
pip install agent-guardian
```

Requires Python 3.10+. Apache-2.0 licensed.

---

## How it compares

| Tool             | Multi-agent swarm | Agentic-AI focus | Standards alignment                           | License        |
|------------------|:-----------------:|:----------------:|-----------------------------------------------|----------------|
| PyRIT            |        no         |        no        | PyRIT risk taxonomy                           | MIT            |
| garak            |        no         |        no        | own taxonomy                                  | Apache-2.0     |
| Promptfoo        |        no         |        no        | OWASP LLM Top 10 + ATLAS + EU AI Act          | MIT            |
| Inspect          |        no         |        no        | own taxonomy                                  | MIT            |
| DeepTeam         |        no         |        no        | OWASP LLM Top 10                              | Apache-2.0     |
| **AgentGuardian**|     **yes**       |    **yes**       | **OWASP ASI 2026 + MITRE ATLAS v5.4.0 + CSA** | **Apache-2.0** |

## Coverage by OWASP ASI 2026 category

All 96 attack probes are distributed across the ten OWASP ASI 2026 categories below. Each finding is triple-tagged with its ASI, MITRE ATLAS, and CSA Agentic-RT identifiers.

- **ASI01** — Memory Poisoning
- **ASI02** — Tool Misuse
- **ASI03** — Privilege Compromise
- **ASI04** — Supply Chain
- **ASI05** — Code Execution
- **ASI06** — Intent Breaking & Goal Manipulation
- **ASI07** — Agent-to-Agent Compromise
- **ASI08** — Cascading Failures
- **ASI09** — Trust Exploitation
- **ASI10** — Rogue Agents (drift)

Enumerate locally with `agent-guardian list-probes`; full catalogue at [agentguardian.io/attacks/overview](https://agentguardian.io/attacks/overview).

---

## 60-second quickstart

```bash
# 1. Sanity check the install (no API key, no network)
agent-guardian doctor

# 2. List the 96 shipped probes
agent-guardian list-probes

# 3. Run an offline scan against the built-in stub target
agent-guardian scan --target stub --mode fast --llm stub

# 4. Open the HTML report
open reports/latest/report.html
```

Stub mode requires **no LLM API key, no network, no environment variables** — it uses canned deterministic responses so you can verify the toolchain end-to-end before pointing it at a real target.

---

## Scan a real agent

```bash
# Against an HTTP endpoint (any framework, any language)
agent-guardian scan \
  --target http://localhost:8000/chat \
  --framework http \
  --mode smart \
  --llm openai \
  --fail-under 80

# Against a LangGraph app
agent-guardian scan \
  --target ./my_graph.py:graph \
  --framework langgraph \
  --mode full
```

Exit code is non-zero if the posture score falls below `--fail-under`, so the same command works inside CI.

---

## Scan modes

| Mode    | What it runs                                              | Typical wall time |
|---------|-----------------------------------------------------------|-------------------|
| `fast`  | High-signal probe subset, single attacker per family      | ~2 min            |
| `smart` | Curated coverage with adaptive attacker selection         | ~10 min           |
| `full`  | Every probe, every applicable attacker, full mutation set | 30+ min           |

Default mode is `full`. Pick `fast` for pre-commit / PR checks, `smart` for nightly runs.

---

## Framework adapters

Shipped first-class adapters (pluggable via `--framework`):

- `langgraph` — LangGraph state graphs
- `crewai` — CrewAI crews
- `openai-agents` — OpenAI Agents SDK
- `autogen` — Microsoft AutoGen
- `adk` — Google ADK
- `strands` — AWS Strands
- `http` — any HTTP/JSON endpoint (works for FastAPI, Flask, Express, anything)

MCP servers and RAG pipelines are covered via the `http` adapter and worked examples under [`examples/`](./examples/) (`examples/mcp_server`, `examples/rag_app`, `examples/fastapi_chatbot`).

---

## Attacker swarm

The core swarm contains **11 attacker agents**, each scoped to a distinct family of agent-stack failure modes:

| Agent                 | Targets                                              |
|-----------------------|------------------------------------------------------|
| `recon-agent`         | Surface mapping, tool discovery                      |
| `goal-hijack-agent`   | Goal redirection, system-prompt override             |
| `tool-abuse-agent`    | Tool misuse, argument injection                      |
| `privilege-agent`     | Privilege escalation, role confusion                 |
| `supply-chain-agent`  | Tool/model/data supply-chain attacks                 |
| `code-exec-agent`     | Sandbox escape, code execution                       |
| `memory-poison-agent` | Long-term memory poisoning                           |
| `a2a-agent`           | Agent-to-agent trust exploits                        |
| `cascade-agent`       | Cascading hallucination / cross-agent contagion      |
| `trust-exploit-agent` | Operator/system trust boundary abuse                 |
| `drift-agent`         | Behavioural drift, policy erosion over conversation  |

Additional specialist classes (`FuzzingAgent`, `OutputHandlingAgent`, `DenialOfWalletAgent`, `DetectionEvasionAgent`, `SecretExtractionAgent`, `IdentityLeakAgent`, `CriticAgent`) ship as building blocks for custom swarms and are documented under [`agentguardian.io/attackers`](https://agentguardian.io/attackers).

---

## Reports & evidence

Every scan produces a timestamped bundle under `reports/<run-id>/`:

- `report.html` — interactive dashboard, drillable per-probe
- `report.pdf` — print-ready evidence (ReportLab)
- `report.sarif` — SARIF 2.1.0 for GitHub Code Scanning / Defender / Snyk ingest
- `report.json` — full machine-readable record
- `evidence/` — per-probe transcripts, prompts, responses, and verdicts

A sample HTML report lives at [`docs/_assets/sample-report.html`](./docs/_assets/sample-report.html).

> **Signing:** the `sign_evidence` config flag is wired but Sigstore-backed signing of the evidence bundle is **planned**, not shipped in 1.0.0. Until then the bundle ships unsigned; the SARIF / JSON / PDF are deterministic and hash-stable for external signing.

---

## Local dashboard

```bash
agent-guardian serve
# → http://localhost:7474
```

Browse historical runs, diff posture scores across releases, and download evidence bundles.

---

## CI integration

```yaml
# .github/workflows/agent-guardian.yml
- uses: actions/setup-python@v5
  with: { python-version: '3.11' }
- run: pip install agent-guardian
- run: agent-guardian scan --target ./agent.py:app --mode smart --fail-under 80 --output sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: reports/latest/report.sarif }
```

Worked examples under [`examples/ci/`](./examples/ci).

---

## Privacy & telemetry

**No telemetry is collected.** `TelemetryConfig.enabled` defaults to `False`. There is no phone-home, no analytics ping, no install tracker. Stub mode additionally requires no network access at all.

---

## Standards mappings

Each probe is tagged with its ASI category, ATLAS technique, and CSA category. Run:

```bash
agent-guardian list-probes --by-standard owasp-asi
agent-guardian list-probes --by-standard mitre-atlas
agent-guardian list-probes --by-standard csa-agentic-rt
```

The honest, auto-generated coverage table lives at [`docs/reference/framework-coverage-matrix.md`](./docs/reference/framework-coverage-matrix.md) — it lists every ATLAS technique the shipped corpus actually cites, and marks zero-coverage CSA categories explicitly rather than hiding them. Full mapping tables also at [`agentguardian.io/standards`](https://agentguardian.io/standards).

---

## Docs

- Quickstart: [agentguardian.io/quickstart](https://agentguardian.io/quickstart)
- Attack catalogue: [agentguardian.io/attacks/overview](https://agentguardian.io/attacks/overview)
- Adapter guides: [agentguardian.io/adapters](https://agentguardian.io/adapters)
- CLI reference: [agentguardian.io/cli](https://agentguardian.io/cli)

---

## Project status

AgentGuardian 1.0.0 is the first stable release. Semver applies to: the public Python API, the CLI surface, the SARIF / JSON report schemas, and the probe IDs. Probe content (prompts, scoring) may evolve within a minor version.

See [ROADMAP.md](./ROADMAP.md) for what is next, [CHANGELOG.md](./CHANGELOG.md) for what shipped, and [governance.md](./governance.md) for how decisions are made.

---

## Contributing

We welcome new probes, new adapters, and new attacker classes. Start with [CONTRIBUTING.md](./CONTRIBUTING.md) and the [`good first issue`](https://github.com/glacien-technologies/agent-guardian/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label.

All commits must be DCO-signed (`git commit -s`). The pre-commit hook will block unsigned commits.

By participating you agree to the [Code of Conduct](./CODE_OF_CONDUCT.md) and the [Ethics Policy](./ETHICS.md) — AgentGuardian is for testing systems you own or are authorised to test.

---

## Community

Join us on [Discord](https://discord.gg/h4FRgxvr) for real-time discussion — probe and adapter design, informal Q&A, and roadmap chat. For long-form questions, use [GitHub Discussions](https://discord.gg/h4FRgxvr); see [docs/community/support](./docs/community/support.mdx) for the full channel matrix.

---

## Security

To report a vulnerability, see [SECURITY.md](./SECURITY.md). Please do **not** open public issues for security reports.

---

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

`AgentGuardian` is a trademark of Glacien Technologies — see [TRADEMARKS.md](./TRADEMARKS.md) for usage guidelines.
