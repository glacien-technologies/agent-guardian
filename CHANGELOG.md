# Changelog

All notable changes to **agent-guardian** are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0rc1] — 2026-05-27

First public release candidate. M1–M15 of the build plan are complete.
After the soft-beta cohort concludes the operator will tag `1.0.0`
and fire the PyPI publish workflow.

### Added

- **M1 — Project scaffolding.** Hatchling build backend, uv-managed
  dev workflow, ruff + mypy strict gating, pre-commit hooks,
  `pip-licenses` dev dependency, project metadata in `pyproject.toml`.
- **M2 — Domain models.** `AsiCategory`, `CsaCategory`, `Severity`,
  `SeverityBand`, `Tier`, `ObservedSurface`, `Probe`, `Finding`,
  `Scan`, `JudgeVerdict`. Frozen dataclasses + Pydantic v2 models.
- **M3 — Core utilities.** Budget controller with token + wall-time
  accounting, sandbox policy, PII redactor (presidio-backed when the
  extra is installed; deterministic fallback otherwise).
- **M4 — Tiering + scoring.** `detect_tier`, the AIVSS formula
  (`compute_aivss`), severity-weighted pass-rates, penalty clamping.
- **M5 — LLM clients.** OpenAI, Anthropic, Bedrock, Vertex AI, Ollama,
  plus a deterministic `StubLLM` / `StubScript` for tests. Retry +
  rate-limit + auth error taxonomy shared across providers.
- **M6 — Prompt strategies.** TAP, MAD-MAX, PAIR, Crescendo as
  pluggable `Strategy` modules with `StrategyContext` / `Turn` types.
- **M7 — Specialist agents.** Eleven agents — `ReconAgent` plus one
  per ASI category — sharing the `AsiAgent` / `Judge` / `JudgeRubric`
  base classes.
- **M8 — Swarm commander.** Layer-3 orchestrator: dispatches recon →
  parallel specialists → checkpoint loop → finalised `Scan`. Observer
  protocol for live UI consumption.
- **M9 — Adapters.** `CodeAdapter`, `PromptAdapter`, `HttpAdapter`
  with pluggable shape modules, framework adapters for LangGraph,
  CrewAI, AutoGen, OpenAI Agents, Strands, ADK.
- **M10 — CLI.** Full Typer command surface (`scan`, `serve`,
  `verify`, `publish`, `report`, `badge`, `last-score`, `doctor`,
  `list-agents`, `list-probes`, `telemetry`). Rich live progress
  panel (`cli_tui`). Per-provider cost estimator (`estimate_scan_cost`).
- **M11 — Seed-probe corpus.** 50 YAML probes (5 per ASI) shipped in
  the wheel. Probe-corpus version stamped at `_meta/version.yaml`.
- **M12 — Dashboard.** FastAPI + Jinja2 server (`agent-guardian serve`)
  with SSE-driven live updates, scan store, dashboard templates and
  assets bundled into the wheel.
- **M13 — Signed reports.** JSON / SARIF / JUnit / Markdown / PDF
  emitters; HMAC-SHA256 + Ed25519 signatures on every JSON report;
  `verify` CLI command + library `verify_signatures` for downstream
  consumers.
- **M14 — Docs site + Docker.** MkDocs Material site published to
  GitHub Pages, multi-stage `Dockerfile`, `docker-compose.yml` for
  the local dev loop.
- **M15 — Pre-launch hardening (this release).**
  - 90% coverage gate enforced in CI (`--cov-fail-under=90`).
  - License-audit CI job rejecting GPL/LGPL/AGPL transitive deps via
    `pip-licenses --fail-on=…`.
  - Hypothesis property tests on the AIVSS formula bumped to 1500
    examples per property (~10 500 cases cumulative).
  - Performance smoke test — T1 stub-LLM scan completes well under 60
    seconds on CI; cost estimate sits inside the documented
    `[$1.00, $2000]` band for the recommended haiku + mini + mini mix
    at 2M tokens.
  - `agent-guardian publish <scan-id>` flow: verifies the M13 signed
    evidence pack, strips per-finding transcripts, writes a redacted
    leaderboard payload, prints the manual-submission placeholder
    pointing operators at the GitHub issue tracker (the server-side
    endpoint is Glacien-edge and will replace the placeholder once
    deployed).
  - arXiv preprint draft (`docs/arxiv-preprint.md`) and operator
    pre-flight checklist (`docs/operator-checklist.md`).
  - Cost estimator + price table exported from the top-level package.

### Known follow-ups (operator-owned)

- PyPI Trusted Publisher setup against `glacien-technologies/agent-guardian`.
- arXiv submission once soft-beta data lands.
- Public leaderboard endpoint deploy
  (`agentguardian.ai/api/v1/leaderboard`).
- `badge.agentguardian.ai` shield endpoint deploy.
- Soft-beta researcher onboarding (PRD §17.3 W-2 cohort).
- Singapore trademark filing (Class 9 + 42) per PRD §12.4.

See `docs/operator-checklist.md` for the full list.

[1.0.0rc1]: https://github.com/glacien-technologies/agent-guardian/releases/tag/v1.0.0rc1
