# AWS Bedrock Release Blockers Design

**Date:** 2026-07-17
**Status:** Approved design, pending implementation
**Branch:** `codex/fix-gcp-redteam-hardening`

## Goal

Make AWS Bedrock scans safe and accurately budgeted by preventing AWS
credentials from entering forensic logs, pricing current Bedrock inference
profile identifiers correctly, and reporting conservative spend for dispatched
requests that finish without a provider usage receipt.

## Evidence and root causes

Live verification used AWS SSO profile `ag-dev`, region `us-east-1`, and model
`us.anthropic.claude-haiku-4-5-20251001-v1:0` at revision
`1e75c4503d793ab7e943f1a807a0bf82bf98e990`.

The direct Bedrock completion succeeded. A `$1.00` functional scan completed 35
requests and 35 responses, and all 46,156 provider tokens appeared exactly once
in each report form. The live gate still failed for the following reasons:

1. `attach_run_log_file()` lowers the root logger to `DEBUG`. Botocore is not in
   the noisy-dependency clamp, so `botocore.parsers` writes SSO
   `GetRoleCredentials` response bodies to `run.log`. The existing redactor does
   not recognize AWS access-key identifiers or AWS credential field names.
2. `BedrockClient` inherits the base pricing identity and returns a bare request
   model. The current dated inference-profile identifier is also absent from the
   price table. Both paths fall through to the `$3/$15` unknown-model rate.
3. `BudgetAdmissionLLM` correctly commits a full reservation when a provider
   request raises or is cancelled, but `SwarmCommander._live_cost_usd()` and
   final report construction only roll up successful `UsageCounter` responses.
   Ledger-only conservative spend is therefore omitted from reports.
4. Post-scan usage folding starts `cost_usd` and `budget.spent_usd` from
   different baselines, allowing them to disagree after summaries.

The credential-bearing scan directories and temporary AWS outputs from this
verification were deleted with user approval. The sanitized report remains at
`.superpowers/sdd/task-aws-live-report.md`.

## Constraints

- Add no runtime dependency.
- Preserve all existing CLI flags and report fields.
- Never log AWS access keys, secret keys, session tokens, SigV4 signatures, or
  populated AWS credential fields at any log level.
- Preserve full AgentGuardian-owned DEBUG diagnostics in `run.log`.
- Do not fabricate observed token usage when a dispatched request has no usage
  receipt.
- A conservative unknown-outcome charge must never be lower than the reserved
  request ceiling and must remain within the admitted cap.
- Successful provider responses must still be counted exactly once.
- Keep uncapped, non-Bedrock, and non-`PromptAdapter` behavior unchanged.
- Use TDD for every production behavior change.
- Every commit must be Conventional Commit formatted and DCO-signed.
- Do not push, merge, deploy, or modify the user's main checkout.

## Design

### 1. AWS log protection

`logging_setup.py` will protect AWS credentials at two independent boundaries.

First, the noisy-dependency clamp will include the `botocore` logger hierarchy.
Attaching a DEBUG `run.log` handler may lower the root logger, but botocore wire,
parser, credential-provider, and endpoint diagnostics will remain at `WARNING`
or higher. AgentGuardian's own DEBUG records remain available.

Second, `redact_secrets()` will recognize and mask:

- `AKIA` and `ASIA` access-key identifiers;
- JSON and Python-repr values for `accessKeyId`, `secretAccessKey`,
  `sessionToken`, and their snake-case variants;
- `X-Amz-Security-Token` values;
- SigV4 `Authorization: AWS4-HMAC-SHA256 ...` values, including credential and
  signature parameters.

This redactor remains active even when an operator explicitly re-enables a
botocore logger after configuration. Tests will feed a synthetic SSO role
credential response through both `redact_secrets()` and a real attached
`run.log` handler. No real credential value will be used in tests.

### 2. Bedrock pricing identity and current inference profiles

`BedrockClient.pricing_model_spec()` will return a provider-qualified identity:
`bedrock:<bare-model-id>`. It will strip an already-present `bedrock:` prefix so
decorator chains cannot produce `bedrock:bedrock:...`.

`cost.py` will recognize the current Claude Haiku 4.5 Bedrock Runtime model
family, including the dated `20251001-v1:0` suffix and supported inference
prefixes. Pricing will distinguish:

- global inference profiles: `$1.00` input / `$5.00` output per million tokens;
- US, EU, AU, JP, and unprefixed regional profiles: `$1.10` input / `$5.50`
  output per million tokens.

The model identity is documented by AWS at:
https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-haiku-4-5.html

The global and geographic rates are documented by AWS at:
https://aws.amazon.com/jp/blogs/news/amazon-bedrock-now-supports-japan-cross-region-inference/

The price-table verification date will advance to `2026-07-17`. Existing
Bedrock models outside the recognized Haiku family retain their current exact
rows or conservative fallback. CLI documentation will use the currently valid
dated model identifier.

### 3. Conservative unknown-outcome spend

The budget ledger remains the source of truth for admission. Successful
responses continue to populate usage counters with observed tokens and exact
request-scoped prices.

For live and final USD calculations, the scan will use:

```text
max(successful-response cost rollup, committed ledger spend)
```

This makes an exception or cancellation visible because
`BudgetAdmissionLLM.complete()` already commits its full reservation on every
`BaseException`. Token totals remain based only on provider usage receipts; an
unknown-outcome reservation contributes dollars but does not invent prompt,
completion, or total tokens.

The resulting rules are:

- rejected pre-dispatch reservation: no provider dispatch and no spend;
- completed response: observed tokens and observed token-priced cost;
- dispatched request without usage: zero observed tokens and the full
  conservative reservation as spend;
- later admissions cannot reuse that reservation.

`cost_usd` and `budget.spent_usd` will share this conservative baseline. The
budget percentage derives from the same value.

### 4. Post-scan accounting consistency

`fold_postscan_usage()` will choose one pre-summary baseline:

```text
base_spend = max(scan.cost_usd, scan.budget.spent_usd)
```

It will then add successful summary usage once and write the same result to
`cost_usd` and `budget.spent_usd`. `tokens_total` continues to add only summary
tokens actually returned by the provider.

This preserves conservative cancellation spend and prevents the report and
budget meter from diverging after optional summaries.

## Error handling and compatibility

- Botocore suppression is logger-level filtering, not exception suppression;
  AWS authentication and provider failures still propagate through existing
  typed errors and AgentGuardian warning/error records.
- Redaction preserves field names and surrounding diagnostic text while
  replacing credential values with the standard redaction marker.
- Unknown Bedrock models remain fail-closed at the existing conservative
  fallback price.
- Ledger drift above a reservation continues to close admission through the
  existing `BudgetLedger.commit()` behavior.
- No schema migration is required.

## Testing strategy

Each behavior begins with a focused failing regression test.

1. Logging tests:
   - synthetic botocore SSO response values are redacted;
   - botocore DEBUG records do not enter a normal DEBUG `run.log`;
   - explicitly re-enabled botocore logging still cannot expose credentials;
   - AgentGuardian DEBUG records remain present.
2. Pricing tests:
   - `BedrockClient.pricing_model_spec()` preserves `bedrock:` identity;
   - global and geographic dated IDs resolve to their exact rates;
   - unrecognized Bedrock IDs retain the conservative fallback;
   - admission and usage tracking use the same resolved rate.
3. Cancellation tests:
   - a dispatched cancelled request commits the reservation;
   - live and final spend include it;
   - observed tokens remain zero;
   - a rejected reservation never dispatches.
4. Post-scan tests:
   - `cost_usd` and `budget.spent_usd` remain equal after summaries;
   - summary usage is included once.
5. Regression gates:
   - focused tests, complete pytest suite, Ruff, formatting, mypy, pre-commit,
     diff check, and package build;
   - direct Bedrock exact-response smoke;
   - bounded `$0.02` hard-cap scan and one `$1.00` functional fallback if the
     hard-cap scan has no tested turns;
   - provider/report token and cost reconciliation;
   - zero AWS credential patterns in console, `run.log`, events, reports, and
     verifier output;
   - zero ANSI false-positive findings;
   - manifest hash/byte verification and raw Ed25519 public-key verification.

## Acceptance criteria

- A live AWS scan produces zero unredacted AWS credential patterns in every
  generated artifact.
- The current US Haiku 4.5 inference-profile ID prices at `$1.10/$5.50`, and
  global prices at `$1.00/$5.00`.
- All completed Bedrock response tokens appear exactly once in final reports.
- A dispatched request without usage causes conservative non-zero spend and
  zero fabricated observed tokens.
- `cost_usd` equals `budget.spent_usd` before and after post-scan summaries.
- The live hard cap is not exceeded.
- Existing GCP verification behavior and all non-AWS providers remain green.
