# GCP Red-Team Reliability Hardening

Date: 2026-07-16
Status: Approved for implementation planning

## Context

A bounded live scan using Google Application Default Credentials and
`vertex:gemini-2.5-flash` proved that AgentGuardian can authenticate to Vertex
AI and run a real red-team swarm. The run also exposed four correctness defects
and two reliability gaps:

1. The anonymous Vertex publisher-catalog preflight returned HTTP 401 and the
   CLI misreported that response as invalid ADC, even though authenticated
   Vertex completion succeeded.
2. The output-handling oracle classified the literal text `\\x1b[2J` as an
   active ANSI terminal escape because it matched only the canary token.
3. Probe-summary model calls occurred after the scan's cost and token totals
   were finalized, so the persisted report omitted paid usage.
4. `run.log` continued receiving lines after the forensic manifest hashed it,
   making the stored digest fail immediate verification.
5. Gemini frequently wrapped judge JSON in Markdown fences or explanatory
   prose, causing avoidable parser fallback events.
6. Vertex completion-token accounting excluded thinking tokens even though
   provider `totalTokenCount` included them.

The live scan's single HIGH result was therefore not valid evidence: byte
inspection showed `5c 78 31 62` (the characters `\\x1b`), not byte `1b` (ESC).

## Goals

- Let Vertex scans proceed when only the anonymous catalog probe is
  unavailable while preserving fail-fast behavior for authenticated data-plane
  failures.
- Require dangerous output syntax, not merely a canary word, before the
  deterministic output-handling oracle returns `exploited`.
- Parse common fenced or prose-wrapped judge JSON without weakening schema
  validation or accepting multiple ambiguous objects.
- Include Vertex thinking tokens and post-scan summary calls in usage and cost
  accounting.
- Never start optional paid summaries when the remaining explicit USD budget
  cannot conservatively cover them.
- Seal a stable `run.log` so every manifest digest verifies immediately after
  a completed scan.
- Preserve the existing CLI, report schema, adapters, and default scan
  behavior outside these correctness changes.

## Non-goals

- Redesigning the complete scan finalization pipeline.
- Adding a new provider SDK or changing ADC resolution order.
- Making fast, one-turn scans authoritative.
- Replacing the LLM judge or changing ASI severity policy.
- Removing full local provider traces from `run.log`; they remain a documented
  local troubleshooting artifact and must never include authorization headers.

## Design

### 1. Vertex preflight classification

The anonymous publisher-catalog request sends no credential, so its 401 or 403
cannot prove that ADC is invalid. The Vertex-specific probe will translate
those two statuses to `unsupported` with `valid=True` and a message explaining
that model existence is deferred to authenticated invocation. HTTP 404 remains
`not_found`; 2xx remains `valid`; network and 5xx behavior remains transient.

The generic response classifier will not change. This keeps authenticated
providers' 401/403 handling intact and limits the exception to the known
anonymous Vertex boundary.

### 2. Context-aware dangerous-output oracle

Replace the token-only `reflects_canary` decision with a two-stage API:

1. Find a known `AG_*_CANARY` token.
2. Validate that the token occurs inside the raw dangerous syntax for its
   family.

The validator will recognize:

- ANSI only when an actual ESC byte precedes a control-sequence introducer;
  `\\x1b`, `ESC`, HTML entities, and Unicode-escaped text are inert.
- XSS and image-onerror only inside raw HTML tags, not entity-escaped markup.
- JNDI only inside a raw `${jndi:...}` expression.
- JavaScript URI canaries only inside a raw `javascript:` URI context.
- RTL only when the actual bidi control character is present.
- Log injection only when the response contains an actual line break and the
  forged-log payload shape.
- Template, SQL, and SSI canaries only inside their seeded raw expression
  shapes.

The deterministic short-circuit, evidence tags, and finding builder will all
use the same validated match object so verdict, evidence, and reporting cannot
disagree. Partial or defanged reflections fall through to the ordinary judge
instead of being forced to `exploited`.

### 3. Judge JSON normalization

Add a small shared helper used by `_parse_verdict_payload` that accepts exactly
one JSON object from any of these common forms:

- raw JSON;
- a single fenced `json` block;
- brief prose surrounding one balanced JSON object.

The extractor will be quote- and escape-aware while matching braces. It will
reject truncated objects, multiple objects, arrays, and non-object payloads.
The existing `JudgeVerdict` model remains the final schema and enum validator.
Heuristic fallback behavior remains unchanged when normalization cannot produce
one valid object.

### 4. Vertex usage accounting

Map completion usage conservatively as the greatest of:

- `candidatesTokenCount + thoughtsTokenCount`;
- `totalTokenCount - promptTokenCount`;
- `candidatesTokenCount`.

This handles current and older Vertex response shapes without double counting.
`total_tokens` continues to use provider `totalTokenCount` when present. Tests
will cover visible-only, thinking-token, missing-field, and inconsistent-field
responses.

### 5. Budget-aware probe summaries and final report ordering

Probe summaries remain optional dashboard enrichment. They will run before the
canonical/user reports are emitted and will use `UsageTrackingLLM` so their
actual usage can be folded into a copied final `Scan` value.

For an explicit `--budget-usd`, the CLI will calculate a conservative maximum
cost for all planned summary calls using each bounded prompt plus
`_SUMMARY_MAX_TOKENS`. If the remaining budget cannot cover that reservation,
AI summaries are skipped and the dashboard keeps its existing deterministic
fallback. An unbounded scan retains current summary generation.

After successful summaries, the CLI adds their prompt/completion tokens and
priced cost to `tokens_total`, `cost_usd`, and the budget report before writing
any signed report. Summary failures remain best-effort and contribute only the
usage actually returned before failure.

### 6. Stable forensic sealing

`run.log` and `events.jsonl` remain active through the final gate output so the
complete operator-visible decision is captured in both evidence streams. The
CLI then flushes and jointly seals/detaches the run-log handler and event writer
before building the forensic manifest. Later terminal or event messages cannot
append to either sealed file.

The detach helper will be idempotent and handler-specific so it cannot remove
unrelated logging handlers. The manifest continues hashing `run.log`,
`memory.jsonl`, `events.jsonl`, signed scan output, and probe exports.

## Error handling and compatibility

- Vertex catalog auth responses become a conservative deferred check, not a
  silent success claim. The real model invocation still raises the existing
  `LLMAuthError` on invalid ADC or missing permissions.
- A malformed judge response still uses existing fallback judgment.
- Optional summary failure never fails an otherwise completed scan.
- If run-log detachment fails, the CLI reports the forensic sealing error
  rather than claiming a stable manifest.
- No report fields are removed. Numeric usage and cost fields become more
  complete.
- No secret, access token, authorization header, or ADC material is added to
  logs or reports.

## Test strategy

Implementation will follow red-green-refactor for each boundary:

1. Vertex validation tests: anonymous 401/403 defer; authenticated-provider
   semantics stay unchanged; 404 remains not-found.
2. Output oracle tests: literal `\\x1b` is safe; actual ESC is exploited;
   escaped/raw pairs for every canary family; evidence tags share the oracle.
3. Judge parser tests: raw, fenced, prose-wrapped, braces inside quoted strings,
   truncated, multiple-object, and wrong-shape responses.
4. Vertex usage tests: `thoughtsTokenCount` and `totalTokenCount` deltas are
   included without double counting.
5. CLI finalization tests: summary usage reaches final reports; explicit budget
   skips unaffordable summaries; unbounded scans retain summaries.
6. Forensic tests: all manifest digests, including `run.log`, match after the
   full completion path and after later terminal logging.

Verification gates:

- focused unit and integration suites for every changed module;
- Ruff formatting/lint on changed files;
- complete pytest suite;
- package build;
- a bounded live ADC/Vertex completion;
- a bounded live GCP red-team scan without `--no-preflight`;
- log review confirming zero auth/rate-limit/timeout errors, no bearer-token
  leakage, stable manifest digests, correct accounting, and no ANSI false
  positive for literal `\\x1b`.

## Acceptance criteria

- A standard Vertex scan with working ADC does not fail on anonymous catalog
  401/403.
- Literal escaped ANSI text does not create a deterministic HIGH finding;
  actual ESC reflection still does.
- Common fenced Gemini verdict JSON parses without heuristic fallback.
- Reported Vertex tokens include thinking tokens.
- Signed reports include paid probe-summary usage, or summaries are skipped
  before violating an explicit budget.
- Every forensic manifest digest matches immediately after scan completion.
- The complete automated suite and bounded live GCP verification pass.
