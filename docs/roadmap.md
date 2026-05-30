# Roadmap

## v1.0 — Foundation (M1–M15, shipping 2026)

The v1.0 release is the eleven-agent swarm with the full standards
alignment matrix.

| Milestone | Deliverable                                                 | Status   |
|-----------|-------------------------------------------------------------|----------|
|  M1       | Scaffolding, CI, license, trademark, README, contrib docs.  | Shipped  |
|  M2       | Tiering truth table + golden fixtures + property tests.     | Shipped  |
|  M3       | Pure-Python AIVSS scorer + per-ASI breakdown.               | Shipped  |
|  M4       | Reconnaissance agent + target profile schema.               | Shipped  |
|  M5       | LLM backends — OpenAI, Anthropic, Bedrock, Vertex, stub.    | Shipped  |
|  M6       | Four jailbreak strategies — PAIR, TAP, Crescendo, MAD-MAX.  | Shipped  |
|  M7       | Shared vector memory + concurrency tests.                   | Shipped  |
|  M8       | Four adapters — prompt, code, HTTP, framework.              | Partial — framework adapter *classes* shipped; CLI dispatch lands in v1.1. |
|  M9       | Swarm Commander + convergence detection.                    | Shipped  |
|  M10      | CLI surface — `scan`, `serve`, `verify`, `report`, `badge`. | Shipped  |
|  M11      | Seed-probe corpus — all ten ASI categories.                 | Shipped  |
|  M12      | FastAPI live dashboard at `localhost:7474`.                 | Shipped  |
|  M13      | Signed evidence packs + report emitters (JSON / SARIF /     |          |
|           | JUnit / Markdown / PDF) with HMAC + Ed25519.                | Shipped  |
|  M14      | Dockerfile + mkdocs-material docs site + README polish.     | Shipping |
|  M15      | PyPI Trusted Publisher + GHCR image + v1.0.0 release.       | Next     |

## v1.1 — 90 days post-v1.0

- **More framework adapters**: PydanticAI, Anthropic Claude Agent SDK.
- **MCP server adapter**: scan a running MCP server directly.
- **Probe authoring DSL**: ship a structured YAML schema for community
  probe contributions, plus a `probe-lint` command.
- **Chain-finding annotations**: link findings that share an attack
  path, with chain bonuses surfaced in the report.
- **Differential mode**: scan the same target twice and diff the
  reports — useful for guardrail tuning and regression detection.

## v1.2 — 180 days post-v1.0

- **CWE alignment**: triple-tag findings with CWE alongside ASI / ATLAS
  / CSA.
- **Cost estimator**: per-scan cost prediction across all LLM backends.
- **Distributed scans**: shard the swarm across multiple workers for
  large target portfolios.
- **GitHub App**: PR-time scanning, badge-as-a-comment, scan-gating on
  AIVSS thresholds.
- **AIVSS v0.9 alignment**: track the OWASP working group's
  ratifications.

## v2.0 — Q4 2026

- **Custom specialist agents**: bring-your-own ASI specialist with a
  pluggable strategy.
- **Continuous monitoring mode**: long-running scans against production
  endpoints with drift detection.
- **Multi-target campaigns**: scan a portfolio of agents under a single
  report.
- **AIVSS v1.0 alignment**: track the final ratified formula.
- **Compliance pack**: SOC2 / ISO 27001 / NIST AI RMF mapping out of
  the box.

## Beyond v2.0

We will see. The agentic-security landscape will look very different in
2027. We want AgentGuardian to be the open framework everyone
agrees the 0–100 score should run on, however the rest of the stack
evolves around it.
