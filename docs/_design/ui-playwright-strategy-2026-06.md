# AgentGuardian UI Playwright Test Strategy

## Goals

"100% coverage" here means **every interactive surface and every SSE-driven state transition** in the dashboard has at least one deterministic Playwright test asserting both DOM state and the cross-check against `report.json` ground truth — across all four tabs (Overview, Findings, Probes, Logs), during-scan and post-scan, plus cross-cutting flows (accessibility, theme, responsive, empty/failed, reload). It does **not** mean pixel-perfect screenshots or branch coverage of internal JS. The LLM enters the loop only **on test failure** — never during a passing run — because the value of an LLM is post-mortem triage of trace bundles, not live test orchestration. Live LLM use would make every run expensive, non-deterministic, and incompatible with the OSS CI budget.

## Architecture

**Playwright Python (sync API) via `pytest-playwright`.** The repo is already pytest-shaped; staying in Python lets fixtures share the FastAPI app's settings, fixture loaders, and `report.json` schema validators. Web-first assertions (`expect(...).to_have_text(...)`) give us auto-retry semantics that match SSE polling for free.

**Two test flows:**

```
                 ┌─────────────────────────────────────────┐
                 │ pytest session (AGENT_GUARDIAN_TEST     │
                 │ _HOOKS=1)                               │
                 └───────────────┬─────────────────────────┘
                                 │ session-scope fixture
                                 ▼
                 ┌─────────────────────────────────────────┐
                 │ uvicorn subprocess (--no-reload)        │
                 │   FastAPI + Jinja + SSE                 │
                 └──┬─────────────────────────────┬────────┘
                    │                             │
        flow (a) during-scan         flow (b) post-scan
                    │                             │
   POST /test/fixtures/load          POST /test/fixtures/load
   GET  /scan/{id}/events.replay     GET  /scan/{id}
   ?speed=20                                     │
                    │                             │
                    ▼                             ▼
            Playwright Chromium ─────────► assertions read both:
                                            • DOM via testids/aria
                                            • #ag-state JSON blob
                                            • report.json fixture
```

**Backend-as-fixture pattern.** A session-scope `uvicorn_server` fixture spawns `uvicorn agent_guardian.server.app:app --no-reload` in a subprocess on a random port, polls `/health` until ready, and yields the base URL. `AGENT_GUARDIAN_TEST_HOOKS=1` mounts the test-only router; the router itself raises at import time if the env var is unset. No in-process `TestClient` (it conflicts with Playwright's loop — FastAPI #5446).

## Scenario inventory (the test plan)

This is the single source of truth — every scenario below is one test function.

**During-scan — Overview (1–9):** status pill "Running", scan ID stable, elapsed timer ticks, agent count grows, probe count monotonic non-decreasing, AIVSS placeholder until `scan_done`, band chips in skeleton, target metadata persists, progress bar monotonic.

**During-scan — Findings (10–17):** stream appends without re-rendering, badge equals row count, every row has severity + ASI tag, default sort stable, mid-scan severity / agent filters compose, zero-state empty message.

**During-scan — Probes (18–22):** one row per agent within 5s, per-agent counter increments, refusal rate updates live, status transitions running→done exactly once, one-finding-per-agent corner case.

**During-scan — Logs (23–26):** tail autoscroll, pause on scroll-up + resume, mid-scan level filter, no duplicate line IDs.

**During-scan — Cross-tab (27–31):** tab switch preserves scroll+filter, home-page band filter respects in-progress, backend crash → "Failed" pill within 5s, abort → "Aborted", export disabled mid-scan.

**Post-scan — Overview (32–38):** pill = "Completed", AIVSS matches `report.json.aivss.score` ±0.1, band matches, per-ASI cells match, refusal rate shown, duration matches `finished_at - started_at` ±1s, target card complete.

**Post-scan — Findings (39–48):** row count = `len(report.findings)`, detail modal opens with full evidence, modal Esc closes + restores focus, each filter (severity/agent/probe/ASI) is exact, AND-composition correct, clear-filters restores total.

**Post-scan — Probes (49–51):** every agent "done", per-agent counts sum to `total_probes`, every row has non-empty AI summary.

**Post-scan — Logs (52–53):** final line is `scan_done`, download produces `.log` matching server-side byte length.

**Post-scan — Export (54–56):** zip button enabled with href, zip contains `report.json` + `run.log` + `findings/*.json` + README, embedded `report.json` parses and matches.

**Cross-cutting — A11y (57–61):** tablist roles + `aria-selected`, arrow-key tab nav, modal focus trap, severity chip WCAG AA contrast both themes, counters use `aria-live="polite"`.

**Cross-cutting — Theme (62–64):** dark Overview legible, dark modal styled, toggle persists across reload.

**Cross-cutting — Responsive (65–67):** 480px Overview stacks, 768px findings collapses to cards, 1024px probes tabular.

**Cross-cutting — Empty/failed (68–72):** zero-scans home CTA, zero-findings message, failed-scan pill + blanked AIVSS, partial findings render, export works on failed scans + includes `crash.log`.

**Cross-cutting — Stability (73–75):** reload mid-scan resumes stream, reload post-scan identical render, two tabs same scan identical state.

Total: 75 tests.

## Instrumentation requirements

**`data-testid` naming: `{region}-{element}[-{identifier}]`, kebab-case.** State lives in `aria-*` and `data-*` attributes, never in extra testids.

| Region | Pattern |
|---|---|
| Tabs | `tabs-button-{overview\|findings\|probes\|logs}`, `tabs-panel-{slug}` |
| Overview | `overview-aivss-score`, `overview-aivss-band`, `overview-kpi-{findings-total\|probes-total\|agents-run\|duration\|refusal-rate}` (each with `data-value="N"`) |
| Findings | `findings-table`, `findings-row-{finding_id}`, `findings-cell-{id}-{column}`, `findings-filter-{severity\|asi\|agent\|probe}`, `findings-filter-clear`, `findings-result-count`, `findings-empty` |
| Probes | `probes-table`, `probes-row-{probe_id}`, `probes-cell-{id}-{column}` |
| Logs | `logs-list`, `logs-row-{seq}`, `logs-filter-{level}`, `logs-search`, `logs-tail-toggle` |
| Modal | `detail-modal` with `data-open` + `data-subject-id`, `detail-modal-title\|body\|close` |
| Export | `export-button-{json\|sarif\|pdf\|zip}`, `export-status` |
| Errors | `js-errors` with `data-error-count="0"` (populated by `window.onerror` + `unhandledrejection`) |

**Custom DOM events (dispatched on `document`, namespace `ag:`):** `ag:tab-switched {from,to}`, `ag:finding-appended {finding_id,total}`, `ag:probe-appended {probe_id,total}`, `ag:log-appended {seq}`, `ag:modal-opened {subject_id,kind}`, `ag:modal-closed`, `ag:sse-connected`, `ag:sse-closed`, `ag:sse-error {message}`, `ag:scan-complete`, `ag:render-complete {component}` (fired inside `requestAnimationFrame`). Tests sync with `page.evaluate(() => new Promise(r => document.addEventListener('ag:scan-complete', r, {once:true})))` — never `waitForTimeout`.

**Test-only endpoints (`AGENT_GUARDIAN_TEST_HOOKS=1` required; module-level guard):**

- `GET /scan/{id}/events.replay?speed=N` — re-emits a persisted SSE log at N× speed; `speed=0` = as-fast-as-consumer.
- `POST /test/fixtures/load {name}` — atomically loads `tests/e2e/fixtures/{name}/report.json` into the in-memory store.
- `POST /test/scan/{id}/crash` — injects a synthetic crash mid-stream for failure-path tests.

**Live-data assertion slots:** every aggregate carries `data-value` on its KPI element; a single `<script id="ag-state" type="application/json">` at end-of-body mirrors `{scan_id, status, counts, last_event_seq}` and is re-serialised on every SSE delta. `last_event_seq` is the canonical sync primitive — wait until `>= N` to assert event-N was processed.

## LLM-on-failure triage pattern

A `pytest_runtest_makereport` hook fires only on `report.failed`. It bundles:

- Playwright `trace.zip` (DOM snapshots + network + console at every step)
- final screenshot
- console messages from `page.on("console", ...)`
- `js-errors` div contents
- failing assertion text + traceback
- test source

The bundle is written to `test-results/{test_id}/`. A `scripts/triage_failure.py` CLI (invoked by a GH Actions `if: failure()` step, **not** by pytest itself) posts it to an LLM with:

```
You are triaging a failed Playwright test for the AgentGuardian dashboard.

TEST: {test_name}
ASSERTION: {assertion_text}
TRACEBACK: {traceback}

CONSOLE MESSAGES (last 50): {console}
JS-ERRORS DIV: {js_errors_json}
FINAL DOM (head + main): {dom_excerpt}
LAST SSE EVENTS (from trace): {sse_tail}

Return JSON only, no prose:
{
  "likely_cause": "selector-drift" | "timing" | "real-bug" | "flake" | "instrumentation-gap",
  "suspected_file": "<relative path>",
  "repro_minimal_steps": ["..."],
  "severity": "p0" | "p1" | "p2",
  "evidence": "<one sentence pointing at the specific console/DOM line>"
}
```

The result is posted as a PR comment. **Off the hot path — zero cost on green runs.**

## Implementation roadmap

| PR | Title | Files touched | Test delta | Risk | Depends on |
|---|---|---|---|---|---|
| 1 | `data-testid` instrumentation | `server/templates/**/*.html` (~20 files), `static/executive_*.js`, `static/live-append.js`, `static/streams.js` (event emits) | +0 (no tests yet) | Low — additive attrs only | — |
| 2 | Test-only endpoints + env gate | new `server/routes/test_hooks.py`, `server/app.py` (conditional mount), `tests/e2e/fixtures/finbot-clean/`, fixture-capture script | +0 | Low — gated by env; raises at import otherwise | PR 1 |
| 3 | pytest-playwright scaffolding + smoke | `tests/e2e/conftest.py` (uvicorn fixture), `tests/e2e/test_smoke.py`, `playwright.config`, `pyproject.toml` deps, `.github/workflows/e2e.yml` (`playwright install --with-deps chromium`) | +10 | Medium — first CI integration; flake-prone if SSE sync uses timeouts | PR 1, PR 2 |
| 4 | Full scenario inventory | `tests/e2e/test_overview.py`, `test_findings.py`, `test_probes.py`, `test_logs.py`, `test_crosscutting.py`, `test_failure_paths.py` | +65 (to 75 total) | Medium — volume; mitigated by `ag:*` events | PR 3 |
| 5 | LLM-on-failure triage | `tests/e2e/conftest.py` (makereport hook), `scripts/triage_failure.py`, workflow `if: failure()` step | +0 | Low — strictly off hot path | PR 4 |

## What 100% coverage explicitly does NOT include

- **Pixel-perfect screenshot regression.** Too brittle for an OSS CI budget; we mask volatile regions in the 3–5 visual smoke shots that PR 4 does include, nothing more.
- **Production-only / cloud-run-mode flows.** The dashboard runs identically locally; cloud-specific paths (auth proxy, paid-tier panels) are out of scope.
- **LLM judge / AIVSS scoring math.** Covered by Python unit tests on `report.json` generation. UI tests only assert that the rendered number equals the report number — not that the report number is correct.
- **Hidden `--framework` white-box mode.** Per launch posture, the public surface is endpoint+prompt+code; framework mode is not part of the UI contract until #126 lands.
- **Backend SSE wire-format conformance.** Tested in `tests/server/`. UI tests treat the stream as ground truth.

## Open questions for the user

1. **Fixture capture authority** — is a finbot-clean scan from the most recent rc release the canonical seed, or do you want a synthesised fixture independent of the live testbench?
2. **CI budget** — acceptable wall-clock for the full 75-test suite on every PR? If <5 min, we shard Findings/Probes across two GH Actions jobs in PR 4.
3. **LLM provider for triage** — Anthropic (Claude) via the existing key the repo already uses for judges, or a separate budget-capped key gated to `if: failure()`?
4. **`#ag-state` blob exposure in production** — keep it always-on (small payload, useful for debugging) or gate behind `AGENT_GUARDIAN_TEST_HOOKS=1`?
5. **Responsive breakpoints** — confirm 480 / 768 / 1024 are the supported targets; the dashboard CSS today doesn't appear to formally claim mobile support, so tests 65–67 may need to be skipped or downgraded to "no horizontal scroll" smoke until a responsive PR lands.
