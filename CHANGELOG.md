# Changelog

## [Unreleased]

### Added

### Changed

### Fixed

## [1.0.0rc12] — 2026-06-09

### Fixed
- **`init` no longer prints the confirmation twice (#110).** Interactive `init` echoed `contract written to <path>` from both the wizard and the CLI; the wizard's echo is dropped so the message prints exactly once in both `--yes` and interactive modes.
- **`validate` target faults are no longer mislabeled as LLM errors (#109).** A target HTTP fault (DNS/connection/5xx) surfaced in the retry log as `LLMTransientError`, reading as if the operator's own judge/attacker model were broken. The target HTTP adapter now raises `TargetTransientError` / `TargetTimeoutError` (subclasses of the LLM error types, so retry/backoff behaviour is unchanged) — the retry log now names the target, not the LLM provider. Applies to contract-driven scans too, since the same transport is shared.
- **`validate --stage X` now limits execution, not just display (#109).** The flag was a display filter — it still ran the full pre-flight, including the slow retrying probe stage. `--stage X` now halts the walk after stage X, so a connectivity-only check (`--stage connect`) no longer pays the probe cost.

## [1.0.0rc11] — 2026-06-09

### Changed
- **Dashboard & CLI UI polish (#121).** Severity bars now reveal their ASI-category breakdown on hover and drill into the Findings tab with the matching severity filter on click; the ASI radar colours each category vertex by its score band so critical/high categories stand out; the Findings and Probes KPI tiles open their tab on click; the Home page gains a copy-able launch command, scan-list refresh / auto-refresh controls, and viewer-localised timestamps; the events view gains per-event JSON copy. The Logs tab no longer claims a completed scan is "updating live" (offering a manual Refresh instead), the scan-plan and probes-table layouts were tightened, and the recon-agent now reports its capability-probe count in the CLI Turns column.

## [1.0.0rc10] — 2026-06-07

### Added
- **Parallel suites / bulk scanning — `agent-guardian suite` (#85).** Run a whole fleet of agents through AgentGuardian in parallel from one YAML file — nightly sweeps, model benchmarks, regression suites. Each workload launches as a separate, fully isolated `agent-guardian scan` subprocess (its own `HOME`, so its scan dir *and* winning-seeds DB are private), bounded by a `concurrency` cap. The runner aggregates a trust-aware cross-scan summary (`summary.json` + a table), collects each workload's report flat at `reports/<name>.<ext>` for every requested format (rendered from the one finished scan, never a second run), and — with `register_scans` (default) — moves each scan into `~/.agentguardian/scans/<id>/` so the dashboard and `report <id>` browse it by its own scan id. Orchestration only: a suite run of one workload is identical to running that one `scan` command. New `suite run` / `suite validate` / `suite summary` commands; see `docs/ci-cd/parallel-suites.mdx` and `examples/suite.yaml`.
- **Corpus-wide `expected_safe_behavior` for all 128 attack probes (#81).** Every probe now carries a concise "what a secure target should do", folded into the judge rubric and stamped on findings (D3 per-probe judging metadata), so verdicts score against the specific probe's expectation, not only the category-level definition.

### Changed
- **Attacker prompting reframed to refusal-resistant "negative security test case" framing (#76).** The default attacker system prompt no longer asks for "attack prompts / jailbreak templates / prompt-injection payloads" and no longer commands "Do NOT refuse" — the vocabulary safety-aligned models (e.g. Gemini) refused ~45% of the time, silently degrading scans to static corpus seeds. It now asks for a realistic input that verifies a named security boundary under operator-owned rules of engagement (OWASP-grounded), keeping the verbatim-to-target output contract. The refusal retry de-escalates ("this is a sandbox QA task") instead of pressuring ("Refusing is not appropriate"). The legacy framing is preserved as `attacker_complete(generation_mode="legacy-redteam")` for operators who supply an uncensored attacker model.

### Fixed
- **Judge verdict JSON no longer truncated by the output-token cap (#84).** The LLM-judge ran with the framework-default 1024-token output budget. For a *thinking* evaluator model (e.g. `gemini-3.5-flash`, whose reasoning tokens count against `maxOutputTokens`) that budget was consumed by reasoning and the verdict JSON was cut off mid-object on ~42% of judge calls — failing to parse and falling back to a heuristic `needs_followup` (conf 0.30, no follow-up probe). That silently degraded ~42% of *all* verdicts and starved the verify-on-needs_followup lane. The judge now requests a generous explicit budget so the JSON always completes; live-verified the heuristic fallback dropped 209→0 and the verify lane recovered.
- **Four self-generating agent lanes now carry probe provenance (#82).** Tool-abuse / memory-poison / a2a / ASI11 agents generate their own prompts and never dispatched corpus seeds, so their probe metadata (and D3 expectations) never reached the judge or findings. They now attach a representative same-category `provenance_seed_id` — kept separate from `seed_id` so finding attribution is never faked — so these lanes carry their category's expected-safe-behavior on judge prompts and findings.
- **Attacker-LLM refusals no longer silently pass as an authoritative "Excellent" score (#76).** When the attacker refuses on too many turns and the scan falls back to static seeds, finalize now consumes the attacker-rejection rate as a scoring gate: ≥30% (FULL) forces `mode_authoritative=False`, and ≥50% forces `scoring_valid=False` with band `NOT_EVALUATED` — the same treatment a stub evaluator gets. The rejection rate + refused-turn count are stamped on the signed `Scan`, surfaced in the CLI scan-end summary ("attacker quality: X% rejection rate …"), and logged to `run.log` (per-turn WARNING + an aggregate finalize WARNING), so a refusal-degraded scan is impossible to mistake for a clean one.

## [1.0.0rc9] — 2026-06-06

### Added
- **`--log-agent-io` — full per-agent LLM I/O in `run.log` for troubleshooting + prompt fine-tuning (PRs #74, #75, #77).** Opt-in flag (or `AGENT_GUARDIAN_LOG_FULL_PROMPTS=1`) that writes every LLM agent's complete input and raw output to the scan's `run.log` as role-tagged `agent-io [<role>]` blocks — **recon, commander, attacker, and judge** — so a single file reconstructs the whole reasoning chain (grep by role, e.g. `grep -A12 "agent-io [attacker]" run.log`). The attacker block folds its red-team system prompt into the logged input, and the recon/commander blocks are logged *before* parsing so unparseable or provider-refused outputs are still captured. Secrets and control characters are redacted via `sanitize_for_log`. Documented in `docs/reference/cli.md` + `cli.mdx`.
- **Enterprise, dashboard-themed PDF report via `--output pdf` (#71).** A reader-friendly, executive-styled PDF — overview, ASI attack-surface coverage, and full findings with untruncated trigger responses — following the dashboard colour theme (WeasyPrint primary, reportlab fallback).
- **Report-format parity (#73).** SARIF, JUnit, Markdown, and GitLab outputs now carry the same posture/config/finding metadata as the JSON/PDF reports (verdict_v2, evidence types, evaluation mode, coverage grade, per-finding properties), with JSON remaining the lossless signed reference.
- **Per-agent probe records + AI summaries + export bundle (#60, #57).** Per-agent probe rows with authoritative per-probe JSON export, AI-generated summaries, and a one-step export bundle, plus recon-modal polish.

### Changed
- **One-click "Export scan data" from the scan page (#61, #63, #62).** The scan page downloads a single zip of logs, probes, and report artefacts directly (renamed from "Download all"); the standalone Files/Export page was removed.
- **Scan-lifecycle status pill (#64, #68).** The dashboard shows In progress (spinner) / Completed / Pending (for interrupted scans) and drops the redundant LIVE freshness dot.
- **CI hardening (#72, #70).** Release attestations + fuzzing targets added; semgrep annotations kept non-blocking.
- **Docs reorg (#67, #69, #65).** Root documentation reorganised, AgentGuardian domains corrected, issue templates simplified.

### Fixed
- **Attacker self-refusals no longer graded as findings (#66).** An attacker LLM's own refusal is recorded as a not-tested marker and excluded from coverage, probe export, and the dashboard — it is not a target compromise.
- **Judge collateral-leak discipline (#58).** Tool-abuse / cascade / memory-poison verdicts no longer claim an unrelated system-prompt leak as their own win.
- **Stale "done" scan status (#57, #54).** Completed scans no longer render as still-running; consolidated live probe-row verdicts.

## [1.0.0rc8] — 2026-06-05

### Fixed
- **Dashboard Overview polish (2026-06-04, PRs #32/#33/#34/#35).** The KPI strip drops the standalone BAND tile (the band already rides on the AIVSS tile's sub-caption) and adds a PROBES tile reporting how many probe attempts were actually dispatched. The ⓘ metric-info button uses a pointer cursor instead of the help question-mark. The "Adversarial Surface Index" radar now renders all ten ASI axes from first paint (it used to collapse to a single spoke early in a scan) and updates live over SSE instead of only on refresh. The COVERAGE tile counts ASI dimensions actually exercised (≥1 probe) rather than only those that produced findings, so a clean-but-tested category still counts and coverage reconciles with the Skipped-agents panel (coverage + skipped span the full taxonomy). The auto-served dashboard no longer briefly renders `unknown scan: <id>` when opened at scan start — the scan directory is pre-created so the separate dashboard process recognises the run immediately.

### Changed
- **Quieter, more readable CLI scan output (2026-06-04).** A scan's terminal now shows the swarm board plus a **compact attack feed** — one concise line per probe (`✓/✗ ASIxx · agent · defended/EXPLOITED`) — instead of a raw `logging` firehose. The full per-call model trace (prompts, responses, phase detail) is written to `~/.agentguardian/scans/<id>/run.log` and the dashboard Logs tab, **decoupled from the terminal**: `AGENT_GUARDIAN_LOG_LEVEL` now controls that captured depth (default DEBUG), while the screen stays quiet unless you pass the global `-v` / `--log-level` to tee raw logs back to the terminal. `--debug` upgrades the compact feed to full per-probe panels; `--debug-format json` is unchanged. The scan-end summary prints the `run.log` path so the full trace is always one `cat` away.
- **Operator-focused dashboard + log/reasoning overhaul (2026-06-04, PRs #25/#26).** Scan dashboard reworked around what the agents actually did rather than internal framework phases: CLI-style scan-plan panel, real-time elapsed timer, repositioned metric tooltips, dropdown finding filters, full-width findings table, a large detail modal (replacing the narrow drawer) with multi-turn attacks rendered as a chat conversation, per-agent probe grouping, and a purpose-built recon view. Judge reasoning is now the judges' raw analysis (no "panel unanimous" jargon; the verdict is the coloured pill) and is no longer truncated. CLI logs show the real request/response and surface provider errors/safety-blocks; preflight validates HTTP status + auth; internal phase codes and per-poll/per-write log spam removed. PII redaction of `memory.jsonl` is now **opt-in** (`AGENT_GUARDIAN_REDACT_PII=1`) so the dashboard shows verbatim target output by default. Each scan auto-serves its own scan-scoped dashboard (opened at scan start), reuse is opt-in, and the stays-up window is 60 minutes.
- **GA-readiness must-fix sweep (2026-06-03).** Reconciliation pass on the top 5 user-perspective gaps from the principal-engineer review:
  - **G1 (Python install)** — README now states the real range (`Python 3.11–3.13`) and the quickstart includes a fallback snippet for the default-macOS Python 3.14 case so the first command on a fresh box has a clear path forward. The Docker (3.11-slim) and GitHub Action (3.12) consumer paths were already insulated.
  - **G2 + G20 (CLI/docs flag drift)** — `contract schema` now defaults to stdout when `--out` is omitted (the docs always said "emits"); `examples/README.md` no longer prints the invalid `--target FOO` flag form (`target` is a positional `typer.Argument`); `docs/reference/cli.md` documents the required `report <SCAN_ID>` positional and softens the misleading "authoritative set" wording for the docs-coverage test.
  - **G3 + G4 (dashboard URL)** — every URL the CLI now prints uses the canonical `/scan/<id>` (singular) so `curl <url>` works on the first hop without `-L`. The server's legacy `/scans/<id>` 307 redirect is intentionally kept so older banner lines captured in operator logs remain clickable, but nothing freshly printed uses the plural form. Quickstart now has a tip-box explaining the TTY requirement for auto-serve.
  - **G5 + G6 (diagnostic clarity)** — `doctor` now prints `pdf engines — weasyprint: X | reportlab: Y` so the line cannot self-contradict (the earlier `pdf engine: none | reportlab 4.5.1` form read as "engine: none"). The CLI scan-end summary humanises the band via the new single-source-of-truth helper `agent_guardian.models.severity.humanise_band` (`band=Not Evaluated (stub mode)` rather than the raw `band=not_evaluated` enum value).
  - **G17 (verify)** — `verify` now distinguishes `HMAC-SHA256: NO-SECRET` from `HMAC-SHA256: FAIL` so a clean self-produced scan without `--secret` no longer reads as a tamper signal.
  - **G23 (sign_evidence)** — `output.sign_evidence` is now documented as a forward-compatibility placeholder; `load_config` accepts existing configs unchanged (no breaking change) but emits a one-shot `DeprecationWarning` so operators know the flag is a no-op until the v1.1 Sigstore work lands. `README.md` Signing note rewritten to match reality.
  - **G28 (README outbound links)** — broken `agentguardian.io/quickstart`, `/attacks/overview`, `/adapters`, `/cli`, `/attackers`, `/standards` links now point at the in-repo `./docs/...` paths that actually exist. README Discord/GitHub-Discussions anchor mismatch corrected.
- README rewritten for honesty: probe count corrected to 96, attacker count corrected to 11, scan modes corrected to `fast`/`smart`/`full`, framework adapter list corrected to LangGraph / CrewAI / OpenAI Agents SDK / AutoGen / ADK / Strands. Removed claim of `examples/vulnerable-agent/` (does not exist) and relabelled Sigstore evidence signing as Planned (config flag exists, implementation not shipped in 1.0.0).
- Product name standardised to `AgentGuardian` (one word) throughout repo.

### Added
- `ETHICS.md`, `SUPPORT.md`.
- Issue templates: probe request, adapter request, documentation.
- Discussion templates: ideas, show-and-tell.
- CodeQL workflow (`.github/workflows/codeql.yml`).
- Operator-facing checklists under `gtm/repo-polish-checklist.md` and `scripts/capture-demo-assets.sh`.


All notable changes to **agent-guardian** are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — Unreleased

### Added

- **Active detection-evasion generation (M3 §5.3) — reverses the earlier coverage-only stance.** `DetectionEvasionAgent` now does both coverage measurement *and* active evasion: new `strategies/evasion.py::EvasionGenerator` takes a request the customer's monitor flagged and rewrites it (rotating techniques — encoding rotation, CoT-length attenuation, multi-turn slow-roll, synonym paraphrase, sleeper-trigger) so it preserves the attack's effect but bypasses that specific monitor, re-checks the detector + (optional) intent judge, and emits a stealth AIVSS modifier (−2…+3). **This is a deliberate reversal of the earlier "we do NOT produce evasion-tuned payloads" caveat** — scoped strictly to authorized detection-coverage testing of the operator's OWN declared monitoring stack under the scan RoE (demonstrating "your monitoring missed this"); it never disables or interferes with the target's guardrails. 7 tests in `test_evasion.py`.
- **M2 CLI surface — the milestone is now reachable from `agent-guardian scan`.** New flags: `--pov-gate` (re-run each finding's trigger and drop unreproducible ones before scoring), `--critic` (adds the LLM rubric Layer-2 on top of the PoV gate), `--bundle DIR` (write the checksummed SARIF+PoV bundle), `--pretext` (rotating social-engineering framing), `--indirect` (trusted-channel injection delivery), and `--owasp-llm` (additionally dispatch the fuzzing / secret-extraction / denial-of-wallet / detection-evasion specialists). All thread into `SwarmConfig`; the `--owasp-llm` path appends `M2_SPECIALIST_AGENTS` to the slate and raises the parallel cap to 14. Default-off so the bare `scan` is unchanged. Tests in `test_cli_m2_flags.py`.
- **M2 follow-ups — critic Layer-2, coverage-guided fuzzing, concurrent strategy racing, detector-replay.** (1) **Critic Layer-2 rubric** wired into the finalize gate behind `SwarmConfig.enable_critic_rubric`: a PoV-passing finding is additionally scored by an LLM rubric (evidence/specificity/novelty/fp_risk via the evaluator LLM) and dropped if quality is too low / FP-risk too high. (2) **Coverage-guided fuzzer** (`strategies/fuzz.py`): an LLM-free, deterministic mutation engine (oversize/control-chars/truncate/type-confusion/encoding mutators) that reduces each response to a behavioural signature and promotes inputs eliciting new signatures back into the corpus — wired as `FuzzingAgent`'s strategy. (3) **Concurrent N-version strategy racing** (`strategies/race_strategies.py`): races orthogonal strategies as independent attack threads (isolated sessions) on the generic `race_first_success` engine, first judge-confirmed compromise wins — complementing the within-thread MAD-MAX racing already live in the agents. (4) **Detector-replay coverage** (`core/detector_replay.py`): replays validated PoVs through a pluggable detector stack and aggregates per-category monitoring coverage, flagging gap categories — the `DetectionEvasionAgent` deliverable (measurement, not evasion payloads). 22 new unit tests.
- **M2 finalize integration — PoV-gate + bundle emission wired into `SwarmCommander`.** `Finding` now captures its `trigger_prompt` so the PoV runner can faithfully replay it. New default-off `SwarmConfig` knobs (`enable_pov_gate`, `pov_runs`, `pov_reliability_gate`, `bundle_dir`): when the gate is on, finalise re-runs each finding's trigger N times against the live target with a semantic judge (the critic's Layer-1 oracle), attaches `pov_reliability`, and drops unreproducible findings **before** AIVSS scoring so they can't inflate the score; findings without a captured trigger are kept ungated. When `bundle_dir` is set, finalise emits the checksummed SARIF+PoV bundle. Default-off keeps the v1 scan path byte-for-byte unchanged (full suite 927 pass). 5 integration tests in `test_pov_gate_finalize.py`.
- **M2 specialist agents — fuzzing (LLM05), secret-extraction (LLM07), denial-of-wallet (LLM10), detection-evasion (coverage).** Four new `agents/*_agent.py` subclassing `AsiAgent`, each declaring the Pattern-8 contract (`allowed_tools` referencing the typed tools, `estimated_cost_per_run_usd`), an OWASP-LLM→ASI mapping for scoring (LLM05→ASI02, LLM07→ASI01, LLM10→ASI08, coverage→ASI10), a methodology `attack_specialization`, a seed corpus, and a `judge_rubric`. Exposed as `agents.M2_SPECIALIST_AGENTS`, kept **separate** from the core ASI01-10 swarm slate so they don't double-run on the agentic-risk scan — the Commander dispatches them for the OWASP-LLM risk set. denial-of-wallet wires the `measure_token_usage` tool (amplification-factor oracle); detection-evasion measures monitoring coverage (no evasion payloads). 15 unit tests in `test_m2_agents.py`. (Deep methodology engines — coverage-guided fuzzing, detector-replay transport — are noted follow-ups.)
- **M2 Wave 4 — N-version racing (P1), parallel-model racing (P4), two-tier triage (P3), ensemble critic (P6).** `core/race.py` provides a generic `race_first_success` (run attempts concurrently, first PoV-validated result wins, losers cancelled) — the shared engine for N-version strategy racing and `core/model_race.py`'s `ModelRacer` (first-valid-success across a panel of `llm/` clients, no LiteLLM). `Strategy` gains `orthogonality_class` + `estimated_tokens` so the racer picks non-overlapping strategies. `core/triage.py` adds `TwoTierTriage` (cheap-score everything, deep-analyze only the top ~20% or whatever fits the budget cap). `agents/critic/` adds `CriticAgent` — Layer 1 re-runs the PoV (reliability gate), Layer 2 scores an injected rubric (evidence/specificity/novelty/fp_risk); no finding bypasses it. 26 unit tests in `test_wave4_patterns.py`.
- **M2 Wave 3 — PoV-as-oracle (Pattern 2) + bundle/SARIF standardization (Pattern 10).** New `core/pov/` package: `PoVScript` (setup/trigger messages + a `SuccessIndicator` — contains/exact/regex/semantic) and `PoVRunner` that re-runs the reproducer N times against the transport with a fresh session each run, scoring `reliability` (observed success rate, gated at 0.8) plus a `wilson_lower` confidence bound honest about small N. `Finding` gains optional `pov_reference` / `pov_reliability`. `reports/sarif.py` result properties now carry the PoV reference/reliability when present; new `reports/bundle.py` assembles a checksummed `bundle_<scan_id>/` (findings.sarif + pov/ + evidence/ + manifest.json) reusing `reports/canonical.py`, with path-traversal sanitization. 21 unit tests (`test_pov.py`, `test_bundle.py`).
- **M2 Wave 2 — budget ledger (Pattern 7) + Commander control surface (Pattern 9).** `core/budget.py` gains a USD-denominated `BudgetEnvelope` + `BudgetLedger` (reserve/commit, per-agent share enforcement, 90%-cap early-stop hook, append-only JSONL audit) alongside the existing token-slice `BudgetController`; `tokens_to_usd` reuses the shared price table. New `core/supervisor.py` (`Supervisor` pause/resume/cancel backed by `asyncio.Event`, wired into the `SwarmCommander` checkpoint loop so an operator cancel trips the existing cooperative-cancel path), `core/bus.py` (`BundleBus` — `asyncio.Queue` + JSONL replay), and `core/scheduler.py` (`EpochScheduler` — re-prioritizes work by score/cost value-density, demotes repeatedly-failing items). 38 unit tests (`test_budget_ledger.py`, `test_supervisor_bus_scheduler.py`) incl. a property test that committed spend never exceeds the cap.
- **M2 Wave 1 — narrow typed tools (Pattern 5) + formalized specialist contract (Pattern 8).** New `tools/` package: `TypedTool` ABC with Pydantic input/output schemas (validated on every call — no shell access), a `ToolRegistry` that enforces each agent's closed allowlist at dispatch (`ToolNotAllowed` is a malformed turn, not an execution), and two transport-coupled concrete tools — `SendUserMessageTool` and `MeasureTokenUsageTool` (reports the output/input amplification factor for the denial-of-wallet specialist). `AsiAgent` gains the `allowed_tools` + `estimated_cost_per_run_usd` class-vars (Pattern 8) the budget ledger and tool dispatch consume; defaults keep the existing 11 agents conformant unchanged. 10 unit tests in `tests/unit/test_tools.py`. (Indicator/finding-coupled tools land with the PoV harness in Pattern 2.)

- **Recon-adaptive attack payloads + tool-output two-step launder.** The attacker now consumes the recon-discovered surface instead of attacking a generic ASI category: `TargetFingerprint.declared_tools` / `declared_memory_keys` flow through `StrategyContext` into the attacker system prompt (`render_surface_brief` in `strategies/base.py`, folded in by `Strategy._attack_system_extra`) and into a surface-aware goal string. New `ToolExfilStrategy` (`strategies/tool_exfil.py`) chains a tool invocation that surfaces sensitive data with a transform/restate step ("summarise the result for my ticket"), laundering it past a direct-disclosure refusal — single-turn primary, multi-turn fallback. `ToolAbuseAgent` races it against PAIR under MAD-MAX when the target exposes tools. Motivation: the 21-target validation matrix showed leaky-but-clean LangGraph samples (KB secrets, cross-session PII) scored 100/EXCELLENT because the attacker only issued naive direct asks. 12 unit tests in `tests/unit/test_recon_adaptive_and_tool_exfil.py`.
- **Recon tool-name discovery.** The recon agent's `tool-inventory` probe already asks the target to list its tools; previously the reply was only checked for a boolean hint and the names discarded, leaving `declared_tools` empty for any target behind a plain `run(prompt)` entry point — which left the recon-adaptive attacker + tool-exfil path inert. Recon now extracts usable tool handles from the reply (LLM extraction via the previously-unused recon LLM, with a backtick/snake_case regex fallback) and populates `TargetFingerprint.declared_tools`. Black-box-friendly: natural-language handles ("knowledge base search tool") work as well as exact function names. 3 new tests in `tests/integration/test_agent_recon.py`. Validated end-to-end: recon now discovers e.g. `search_glacien_kb` / `lookup_contacts` and the tool-exfil strategy crafts correct tool-naming payloads. **Remaining barrier (not a recon gap):** on the benchmark targets the laundering attacks still don't extract secrets because (a) Gemini's alignment refuses transparently credential-framed asks and (b) the attacker guesses tool arguments that miss the KB's actual keys — both addressed by the planned pretext-framing + tool-arg-enumeration improvements, not by recon.
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

**First stable, generally-available release.** Production/Stable status on PyPI; the package
metadata, classifiers, and badges all reflect GA. This entry consolidates the M1–M15 build
content plus the engineering-standards hardening pass below — `1.0.0rc1` is retained as a
historical tag pointer at the bottom of this file but its scope is fully subsumed here.

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

> **Historical record only.** This release candidate was promoted to `1.0.0` (above) the
> same day after the soft-beta hardening pass. The bullets below describe the M1–M15
> build content that landed in the RC and is now part of GA — they are retained verbatim
> for changelog completeness; no separate RC artifact ships from PyPI.

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

[1.0.0rc12]: https://github.com/glacien-technologies/agent-guardian/releases/tag/v1.0.0rc12
[1.0.0rc11]: https://github.com/glacien-technologies/agent-guardian/releases/tag/v1.0.0rc11
[1.0.0rc10]: https://github.com/glacien-technologies/agent-guardian/releases/tag/v1.0.0rc10
[1.0.0rc1]: https://github.com/glacien-technologies/agent-guardian/releases/tag/v1.0.0rc1
