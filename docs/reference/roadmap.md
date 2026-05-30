# Roadmap

**TL;DR.** What's shipped, what's in flight, and what's planned, with
dates and semver windows. Honest about preview / not-yet-implemented
work — if a feature isn't here, it isn't planned. For per-release detail
see [reference / changelog](changelog.md).

## v1.0 — Foundation (shipped)

The v1.0 release is the eleven-agent core swarm plus the four
OWASP-LLM specialists, the full standards-alignment matrix, the signed
evidence pack, and the CLI / API / dashboard surface. Released as
`1.0.0` on 2026-05-27.

| Date       | Deliverable                                                                                                        | Status   | M#  |
|------------|--------------------------------------------------------------------------------------------------------------------|----------|-----|
| 2026-05-26 | Scaffolding, CI, license, trademark, README, contrib docs.                                                         | Shipped  | M1  |
| 2026-05-26 | Tiering truth table + golden fixtures + property tests.                                                            | Shipped  | M2  |
| 2026-05-26 | Pure-Python AIVSS scorer + per-ASI breakdown.                                                                      | Shipped  | M3  |
| 2026-05-26 | Reconnaissance agent + target profile schema.                                                                      | Shipped  | M4  |
| 2026-05-26 | LLM backends — OpenAI / Anthropic / Bedrock / Gemini AI Studio / Ollama / stub; Vertex preview (full transport in v1.1). | Shipped  | M5  |
| 2026-05-27 | Four jailbreak strategies — PAIR, TAP, Crescendo, MAD-MAX.                                                         | Shipped  | M6  |
| 2026-05-27 | Shared vector memory + concurrency tests.                                                                          | Shipped  | M7  |
| 2026-05-27 | Four adapters — prompt + code + HTTP + six framework adapters with live `--framework KIND` CLI dispatch.            | Shipped  | M8  |
| 2026-05-27 | Swarm commander + convergence detection.                                                                           | Shipped  | M9  |
| 2026-05-27 | CLI surface — `scan`, `serve`, `verify`, `report`, `badge`, …                                                      | Shipped  | M10 |
| 2026-05-27 | Seed-probe corpus — all ten ASI categories.                                                                        | Shipped  | M11 |
| 2026-05-27 | FastAPI live dashboard at `localhost:7474`.                                                                        | Shipped  | M12 |
| 2026-05-27 | Signed evidence packs + report emitters (JSON / SARIF / JUnit / Markdown / PDF) with HMAC + Ed25519.               | Shipped  | M13 |
| 2026-05-27 | v1.0 docs site, Docker image, README polish.                                                                       | Shipped  | M14 |
| 2026-05-27 | PyPI publish + GHCR image + `v1.0.0` release.                                                                      | Shipped  | M15 |

## v1.1 — Target: 2026 Q3 — semver `1.1.x`

The minor that closes the launch-readiness backlog. Each line below
ships either as additive surface or behind an explicit flag; default
behaviour for v1.0 users is preserved except for the
[`--mode` default flip](migration.md#breaking-default-change-scans-without-mode-now-run-full).

### Adapters

- **LangChain adapter** — wrap `Runnable` / `Chain` objects through
  `FrameworkAdapter`.
- **MCP server adapter** — scan a running MCP server directly.
- **Azure OpenAI adapter** — first-class provider client (today: use the
  generic OpenAI client with a base URL override).
- **Anthropic Claude Agent SDK adapter** — wrap `claude-agent-sdk` agent
  objects.
- **PydanticAI adapter** — wrap `pydantic-ai` agents.
- **LlamaIndex adapter** — wrap `LlamaIndex` query engines / agents.

### Framework adapter demo targets

Tier-aligned demo targets in `examples/` to match the existing
LangGraph / OpenAI Agents trios:

- **CrewAI** — T4 / T3 / T1 trio.
- **AutoGen** — T4 / T3 / T1 trio.
- **Strands** — T4 / T3 / T1 trio.
- **Google ADK** — T4 / T3 / T1 trio.

### Observability & operations

- **Consumer-side OTel exporter** — out-of-process exporter binary so
  customers can drop GenAI spans into their existing collector without
  importing the package.
- **`agentguardian_events_dropped_total` Prometheus counter** —
  expose dropped-event counts on `/metrics`.
- **`serve --token` / `serve --insecure-no-auth` CLI flags** —
  promote the existing `AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN` env to a
  first-class CLI flag (and sync the docstring in `server/auth.py`).

### Verification & gating

- **`last-score --score-only` refuses on non-authoritative scans** —
  emit a stderr error + exit `1` instead of returning a vacuous score
  from a stub run.
- **`last-score --require-authoritative` flag** — opt-in stricter
  gate that fails when `mode_authoritative` is `false`.
- **`verify` renders `HMAC-SHA256: SKIPPED (no secret)`** instead of
  the current `FAIL` when no `--secret` / `AGENT_GUARDIAN_SIGNING_SECRET`
  is supplied. The verifier still treats the channel as untrusted; the
  rendering change is for operator clarity. See
  [reference / cli — verify](cli.md#verify).

### Branding & content

- **`agentguardian.io` rebrand sweep** in source literals.
  `reports/sarif.py:96` (`SARIF_INFO_URI`),
  `telemetry/prompt.py:135`, `telemetry/client.py:46`, and the
  `server/templates/analytics.html` footer still carry the legacy
  `agentguardian.ai` literal. The literals are stable
  trust anchors in shipped JSON/SARIF, so the rebrand needs a coordinated
  release.
- **Research preprint Results section** — fill the placeholder in
  [research / preprint (draft)](../research/preprint.md).

## v1.2 — Target: 2026 Q4 — semver `1.2.x`

- **CWE alignment** — triple-tag findings with CWE alongside ASI /
  ATLAS / CSA.
- **Cost estimator** — per-scan cost prediction across all LLM
  backends.
- **Distributed scans** — shard the swarm across multiple workers for
  large target portfolios.
- **GitHub App** — PR-time scanning, badge-as-a-comment, scan-gating on
  AIVSS thresholds.
- **AIVSS v0.9 alignment** — track the OWASP working group's
  ratifications.

## v2.0 — Target: 2027 H1

- **Custom specialist agents** — bring-your-own ASI specialist with a
  pluggable strategy.
- **Continuous monitoring mode** — long-running scans against
  production endpoints with drift detection.
- **Multi-target campaigns** — scan a portfolio of agents under a
  single report.
- **AIVSS v1.0 alignment** — track the final ratified formula.
- **Compliance pack** — SOC2 / ISO 27001 / NIST AI RMF mapping out of
  the box.

## Beyond v2.0

We will see. The agentic-security landscape will look very different in
2027. We want AgentGuardian to be the open framework everyone agrees
the 0–100 score should run on, however the rest of the stack evolves
around it.

## Milestone decoder (contributors)

The internal milestone labels (`M1`–`M15`) used in the v1.0 build and
in the [v1.1.0 changelog entry](changelog.md) map to user-facing
deliverables as follows. End users should ignore this column; it exists
so contributors navigating the codebase can connect a commit message or
code comment to a shipped feature.

| M#  | User-facing label                                                                                                     |
|-----|-----------------------------------------------------------------------------------------------------------------------|
| M1  | Project scaffolding, CI, contribution docs.                                                                           |
| M2  | Target tiering rules + golden test fixtures.                                                                          |
| M3  | AIVSS scorer + per-ASI breakdown.                                                                                     |
| M4  | Reconnaissance agent + target profile schema.                                                                         |
| M5  | LLM provider clients.                                                                                                 |
| M6  | Jailbreak strategies (PAIR, TAP, Crescendo, MAD-MAX).                                                                 |
| M7  | Shared swarm memory.                                                                                                  |
| M8  | Target adapters (prompt, code, HTTP, framework).                                                                      |
| M9  | Swarm commander + convergence detection.                                                                              |
| M10 | CLI surface.                                                                                                          |
| M11 | Seed-probe corpus.                                                                                                    |
| M12 | Local dashboard at `localhost:7474`.                                                                                  |
| M13 | Signed evidence packs (HMAC + Ed25519) and the JSON / SARIF / JUnit / Markdown / PDF report emitters.                 |
| M14 | v1.0 documentation site, Docker image, README polish.                                                                 |
| M15 | PyPI / GHCR publish + `v1.0.0` release.                                                                               |
