# Roadmap

## Planned — not yet shipped

- **Sigstore-signed evidence bundles.** The `sign_evidence` config flag is wired but the
  Sigstore signing pipeline is not yet implemented. Target: 1.1. Until then, the SARIF / JSON /
  PDF report artifacts are deterministic and hash-stable so they can be signed externally.
- **First-party MCP and RAG adapters.** Today MCP and RAG are covered via the `http` adapter
  and worked examples (`examples/mcp_server`, `examples/rag_app`). First-class `--framework mcp`
  and `--framework rag` adapters are on the 1.2 roadmap.


This file is the canonical roadmap for AgentGuardian OSS.
It tracks the **current 90-day thematic cycle** only.

- The Mintlify-rendered companion lives at [`docs/community/roadmap.mdx`](roadmap.mdx) and links here.
- Live progress is on the [GitHub Projects board](https://github.com/orgs/glacien-technologies/projects).
- Anything not in this file is **not** a public commitment.

## How this roadmap works

- **Time-bucketed, not version-locked.** We do not promise that a given item ships in v1.1, v1.2, or by any specific date. We commit to the *theme* for the cycle.
- **Cycle length: ~90 days.** The current cycle refreshes on each tier-3 governance review per [`governance.md`](governance.md). Previous cycles' deliverables are visible in [`CHANGELOG.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md) and the git log.
- **No timelines inside the cycle.** Within a cycle, items move from "Now" to "Next" to "Later" as they get picked up, but there is no week-by-week schedule.
- **Influence the roadmap.** File a
  [roadmap-candidate issue](https://github.com/glacien-technologies/agent-guardian/issues?q=is%3Aissue%20label%3Akind%2Froadmap-candidate)
  or — most effective — ship a PR.

## Current cycle — 2026-Q3 (June – August 2026)

### Theme 1 — Probe coverage expansion

Grow the OWASP ASI 2026 corpus where the agent-attack literature has moved
fastest since v1.0.

- **ASI-10 (rogue agent / drift) long-horizon probes** that span multiple
  scan windows, so drift-style attacks reach their payoff turn instead of
  being early-stopped.
- **ASI-04 (supply chain) MCP-registry probes** as the MCP server ecosystem
  matures and registry-side compromise becomes a realistic vector.
- **ASI-09 (trust exploitation) output-channel probes** — artifact rendering,
  agentic-document tampering, downstream-tool trust.

### Theme 2 — Enterprise-adapter hardening

Tighten the adapters real users are wiring AgentGuardian into.

- **Deeper OpenAI Agents SDK** coverage (assistants, parallel tool calls,
  streaming).
- **Anthropic Computer-Use and tool-use** path coverage.
- **A2A v1.0 protocol** coverage as the spec stabilises.
- **Streaming-response defaults** across every adapter so probes
  don't have to disable streaming to get a clean transcript.

### Theme 3 — Supply-chain security & trust signals

Make AgentGuardian's own supply-chain story easy to verify and easy to cite.

- **OpenSSF Best Practices badge** enrolment at
  [bestpractices.dev](https://www.bestpractices.dev). Tracking doc:
  [`docs/security/openssf-badge-status.md`](../security/openssf-badge-status.md).
- **Reproducible-build verification record.** First independent
  byte-for-byte rebuild attestation appended to
  `docs/security/reproducible-builds.md` per the protocol already documented
  there.
- **Disclosure-history publication discipline.** Every closed advisory
  recorded in `docs/security/disclosure-history.md` within seven days of
  embargo expiry — turning the file into a continuous record rather than a
  scaffold.

### Theme 4 — Report & CI integration polish

The output paths most adopters touch first.

- **Reusable GitHub composite action** so wiring AgentGuardian into a
  workflow stops being a hand-written `pip install` step.
- **SARIF 2.1.1 cross-platform parity** across GitHub Security, GitLab
  code-scanning, and Azure DevOps.
- **`--diff-against`** flag so PR scans compare against the main-branch
  baseline instead of re-scoring from zero on every push.

### Theme 5 — Developer experience

Smaller items that compound across daily use.

- **`agent-guardian inspect <probe-id>`** for offline probe debugging
  without dispatching the full swarm.
- **Richer per-agent status lines** in the terminal progress view.
- **`--profile fast-iteration`** preset for tight local dev loops.

## Explicit non-goals for this cycle

These are deferred — by deliberate scoping, not because they are unwanted.

- **CodeQL integration.** Tracked as a future-cycle candidate. Scorecard +
  Bandit + Semgrep + Gitleaks already cover the SAST signal we need to gate
  PRs. CodeQL adds value but adds maintenance; we will not commit to it
  inside a cycle we cannot resource.
- **Runtime defensive controls.** AgentGuardian is a *testing* framework,
  not a runtime gateway. Runtime enforcement, policy proxying, and live
  traffic interception are out of scope for OSS and belong to AgentGuardian
  Enterprise.
- **Managed evidence storage, team / SSO / audit-log workflows,
  telemetry.** Same scoping — see [Open vs Enterprise](../concepts/open-vs-enterprise.mdx).

## Last cycle's deliverables

A reverse-chronological record lives in [`CHANGELOG.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/CHANGELOG.md).
Everything that landed in the previous cycle (M1–M15 build through v1.0.0,
plus the v1.1 in-flight items) is enumerated there with the merging PR's
commit and test count.

## Maintaining this file

Edits to this roadmap are a tier-3 governance change per
[`governance.md`](governance.md) — three of four maintainer roles
concurring, decision recorded in the quarterly review minutes under
`docs/engineering-standards-reviews/`. Cycle refresh is one such tier-3
event; the next refresh is scheduled for the 2026-Q4 review.

---

*Cycle: 2026-Q3. Last revised: 2026-06-01.*
