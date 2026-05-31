# Fact sheet

Structured facts for newsletter editors and writers. Update on every
release.

## Project

| Field                  | Value                                                      |
| ---------------------- | ---------------------------------------------------------- |
| Name                   | AgentGuardian                                              |
| Tagline                | Open-source red teaming for AI agents.                     |
| License                | Apache-2.0                                                 |
| Current version        | v1.0.0                                                     |
| First public release   | 2026                                                       |
| Repository             | https://github.com/glacien-technologies/agent-guardian     |
| PyPI                   | https://pypi.org/project/agent-guardian/                   |
| Docs                   | https://agentguardian.io                                   |
| Live testbench         | https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app   |
| Docker image           | ghcr.io/glacien-technologies/agent-guardian:latest         |

## Technical

| Field                     | Value                                                                                                |
| ------------------------- | ---------------------------------------------------------------------------------------------------- |
| Languages                 | Python 3.11+                                                                                         |
| Standards alignment       | OWASP ASI 2026 · MITRE ATLAS v5.4.0 · CSA Agentic AI Red Teaming Guide                               |
| Scoring                   | AIVSS 0–100, deterministic, formula at https://agentguardian.io/reports/aivss-score                  |
| Output formats            | SARIF · JSON · JUnit · Markdown · PDF                                                                |
| Supported targets         | LangGraph · CrewAI · OpenAI Agents SDK · MCP servers · RAG apps · REST endpoints · custom Python     |
| Local-first               | Yes — no telemetry, no signup, no cloud dependency for the scanner                                   |
| Reproducible build        | Yes — `SOURCE_DATE_EPOCH` set from commit timestamp                                                  |
| Signed releases           | Sigstore keyless via Fulcio + Rekor; CycloneDX SBOM attached                                         |

## Methodology

| Field                       | Value                                                                                          |
| --------------------------- | ---------------------------------------------------------------------------------------------- |
| Architecture                | Swarm of 14 specialist adversarial agents coordinated by a Swarm Commander LLM                 |
| Convergence detection       | Jaccard overlap > 0.6 on (technique, target-surface) tuple                                     |
| Swarm advantage (empirical) | 2.3x more unique finding-classes vs serial in the same wall-clock budget                       |
| Pre-print                   | https://agentguardian.io/arxiv-preprint                                                        |

## Company

| Field                  | Value                                                |
| ---------------------- | ---------------------------------------------------- |
| Company name           | Glacien Technologies                                 |
| Website                | https://glacien.ai                                   |
| Founder                | See `founder-bio.md`                                 |
| Security contact       | security@glacien.ai (PGP key in SECURITY.md)         |
| General contact        | hello@glacien.ai                                     |
| Press contact          | press@glacien.ai                                     |

## What AgentGuardian is not

| Misconception                                  | Correction                                                                                          |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| "A hosted SaaS scanner"                        | The OSS toolkit is local-first; no hosted scanner exists today.                                     |
| "An LLM evaluation framework"                  | AgentGuardian is adversarial red-teaming, not output evaluation. See https://agentguardian.io/concepts/how-agentguardian-works. |
| "A successor to PyRIT / garak"                 | Complementary: PyRIT and garak are single-chain probes; AgentGuardian is a coordinated swarm.       |
| "AI-generated marketing site"                  | Every doc, every probe, every line of code is human-authored and code-reviewed.                     |
| "Will phone home"                              | The scanner has no network egress beyond the LLM API and the optional report-upload endpoint.       |
