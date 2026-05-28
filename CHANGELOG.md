# Changelog

All notable changes to **agent-guardian** are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — Unreleased

### Added

- **Recon-adaptive attack payloads + tool-output two-step launder.** The attacker now consumes the recon-discovered surface instead of attacking a generic ASI category: `TargetFingerprint.declared_tools` / `declared_memory_keys` flow through `StrategyContext` into the attacker system prompt (`render_surface_brief` in `strategies/base.py`, folded in by `Strategy._attack_system_extra`) and into a surface-aware goal string. New `ToolExfilStrategy` (`strategies/tool_exfil.py`) chains a tool invocation that surfaces sensitive data with a transform/restate step ("summarise the result for my ticket"), laundering it past a direct-disclosure refusal — single-turn primary, multi-turn fallback. `ToolAbuseAgent` races it against PAIR under MAD-MAX when the target exposes tools. Motivation: the 21-target validation matrix showed leaky-but-clean LangGraph samples (KB secrets, cross-session PII) scored 100/EXCELLENT because the attacker only issued naive direct asks. 12 unit tests in `tests/unit/test_recon_adaptive_and_tool_exfil.py`. **Known limitation:** this path only activates when `TargetFingerprint.declared_tools` is populated. `CodeAdapter` introspection only finds tool attributes on the entry callable, and the recon agent currently sets `has_tools` behaviorally without extracting tool *names* — so for targets that expose a plain `run(prompt)` entry point (the common LangGraph case), `declared_tools` is empty and the path stays inert. Validation against the benchmark targets confirmed no new findings yet; the unblocker is recon tool-name discovery (tracked for the M2 recon enhancement).
- **Three explicit scan modes — `fast`, `smart`, `full` (default).** New `--mode` / `-m` flag on `agent-guardian scan`. Picks documented in `docs/concepts/scan-modes.md` and reproduced in `--help`. Empirical numbers below from the vulnerable-by-design target (`agentguardian-benchmarks/targets/vulnerable/owasp_asi_all.py`) on Gemini 2.5 Flash:
  - **`fast`** — CI gate / smoke check. Top-3 probes per agent, 4-turn cap, aggressive early-stop. ~165s, ~$0.016, ~32k tokens.
  - **`smart`** — v1.0 default. Full corpus, 12-turn budget, early-stop on AIVSS variance + no-recent-findings. ~190s, ~$0.019, ~38k tokens.
  - **`full` (new default)** — Full corpus, 12 turns, early-stop effectively disabled (gated until every agent has used its full budget). ~365s, ~$0.030, ~66k tokens.
- **Mode is recorded on every `Scan` report** (`mode` field in the JSON) and on every `ScanCompletedEvent` telemetry payload (ESSENTIAL tier — operational, not identifying — so the public dashboard can break down findings by mode without re-bucketing legacy data as FULL).
- **`ScanMode` enum** and `_MODE_PRESETS` table on `SwarmConfig` for programmatic callers. Per-mode knobs (`probes_per_category`, `max_turns_per_agent`, `min_turns_before_early_stop`) auto-populate from the preset; an explicit override always wins so tests can compose e.g. `SwarmConfig(mode=FULL, max_turns_per_agent=4)`.
- **18 unit tests in `tests/unit/test_swarm_modes.py`** covering preset wiring, the `_checkpoint` gate behaviour for each mode, CLI flag routing, JSON round-tripping on the `Scan` model, and telemetry-event serialisation.

### Changed

- **BREAKING DEFAULT CHANGE — scans without `--mode` now run `full`.** Pre-v1.1 scans implicitly ran the equivalent of `smart`; the default flips to `full` because for a security tool, the right failure mode is "you paid 2× more for thorough coverage" not "you got a fast misleading score." To restore the v1.0 cost/wall profile, pass `--mode smart`. The flag's `--help` text spells out the cost/duration trade-offs.

### Fixed

- **EARLY_STOP bias against slow-burn attack categories.** The v1.0 `_checkpoint` returned EARLY_STOP whenever AIVSS variance dropped below threshold **and** no findings had landed in the last checkpoint window. The second condition fires after any quiet window, silencing goal-hijack / memory-poisoning / trust-exploitation agents that legitimately take longer to land their first finding. v1.1 keeps that v1.0 behaviour on `smart` (unchanged) but adds a `min_turns_before_early_stop` gate that `full` mode sets to 999 (>> per-agent max turns of 12), so FULL mode's checkpoints always return CONTINUE. Mode-validation runs against the vulnerable-by-design target show FULL using ~2× the wall time of SMART (365s vs 190s) — confirming early-stop is genuinely suppressed. ASI coverage between modes is target-dependent and LLM-stochastic; FULL's value is removing the *risk* of an over-eager EARLY_STOP rather than a guaranteed coverage-count improvement on every target.

## [1.0.0] — 2026-05-27

First stable release. Promotes the contents of `1.0.0rc1` to General Availability after the soft-beta cohort and the engineering-standards hardening pass below.

### Added

- **EARLY_STOP actually cancels.** Cooperative cancellation between `SwarmCommander` and `AsiAgent`: agents observe a shared `asyncio.Event` at each turn boundary and exit cleanly with `terminated_by="cancelled"` rather than running to natural budget. The EARLY_STOP log message is now honest about its semantics. Empirical effect on the LangGraph T3 verification target: parallel phase 337s → 28s (92% reduction).
- **Live Dashboard — Coverage page.** New route `GET /scan/{id}/coverage` rendering a 5-row coverage matrix (OWASP 10 cells, MITRE ATLAS 10 tactics, CSA 12 categories, AIVSS 6 sub-scores, attack strategies 5 cells) plus a paginated findings table with severity / ASI / free-text filters. Self-contained chrome to preserve the design's editorial-tech aesthetic. 19 dedicated tests.
- **OpenSSF Scorecard workflow** at `.github/workflows/scorecard.yml`, weekly cron + push trigger.
- **Sigstore signing + CycloneDX SBOM** in the publish workflow — every wheel, sdist, and SBOM gets a keyless OIDC signature attached to the GitHub Release; PEP-740 attestations attached to PyPI.
- **Bandit + Semgrep + Gitleaks** wired into CI (`sast` and `secret-scan` jobs).
- **Dependabot** configured for `pip`, `github-actions`, and `docker` ecosystems.
- **Brand-integrity workflow** enforcing `@glacien.ai` author emails on `main`.
- **MAINTAINERS.md, .github/CODEOWNERS, governance.md** — corporate-backed governance documented in public.
- **Reproducible-build documentation** at `docs/security/reproducible-builds.md` with byte-for-byte verification protocol and annual independent-verification table.
- **Public disclosure-history log** scaffolded at `docs/security/disclosure-history.md`.
- **Deprecation policy** documented at `docs/contributing/deprecation-policy.md` — six-month notice, DeprecationWarning, CHANGELOG flagging.
- **5 additional README badges** per Standard §11.1: Coverage, OpenSSF Scorecard, OpenSSF Best Practices, PyPI downloads, Discord.

### Changed

- **`pyproject.toml` development status** Alpha → Production/Stable. Added Linux/macOS/Windows OS classifiers, `Typing :: Typed`, `Python 3 :: Only`.
- **`SECURITY.md`** — added scope/disclosure history pointers, replaced GPG `TBD` with a `_pending_` placeholder until the key-ceremony lands, documented Sigstore verification path.
- **Bandit added to dev extras** (`pyproject.toml`) so `uv sync --extra dev` brings it in for the CI `sast` job.

### Fixed

- **Silent except handlers in coverage filter** — `_filter_findings` now logs a `_LOG.debug` line when an invalid severity or ASI query param is ignored, satisfying the no-silent-failures mandate enforced by `test_no_silent_excepts_in_src`.

### Security

- **Signed releases mandatory.** The publish workflow refuses to upload if Sigstore signing fails. Verifiable via `sigstore verify` against the published workflow identity.

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
