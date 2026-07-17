# AWS Bedrock Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent AWS credential leakage, price current Bedrock Claude Haiku 4.5 inference profiles correctly, and preserve conservative spend for dispatched requests without usage receipts.

**Architecture:** Harden logging at both the dependency-level and value-redaction boundaries. Preserve Bedrock's provider-qualified pricing identity and resolve the current model family by its AWS inference-profile shape. Reconcile successful-response cost with the shared budget ledger so final reports retain conservative unknown-outcome spend without fabricating tokens.

**Tech Stack:** Python 3.11+, asyncio, botocore, httpx, Pydantic v2, pytest/pytest-asyncio, Ruff, mypy, pre-commit, existing `BudgetLedger`, existing report signing.

## Global Constraints

- Add no runtime dependency.
- Preserve all existing CLI flags and report fields.
- Never log AWS access keys, secret keys, session tokens, SigV4 signatures, or populated AWS credential fields at any log level.
- Preserve full AgentGuardian-owned DEBUG diagnostics in `run.log`.
- Do not fabricate observed token usage when a dispatched request has no usage receipt.
- A conservative unknown-outcome charge must never be lower than the reserved request ceiling and must remain within the admitted cap.
- Successful provider responses must still be counted exactly once.
- Keep uncapped, non-Bedrock, and non-`PromptAdapter` behavior unchanged.
- Every production change follows red-green-refactor TDD.
- Every commit uses a Conventional Commit prefix and `git commit -s`.
- Work only in `/Users/mobionix/.config/superpowers/worktrees/agent_guardian_oss/fix-gcp-redteam-hardening` on `codex/fix-gcp-redteam-hardening`.
- Do not push, merge, deploy, or modify the user's main checkout.

---

### Task 1: Prevent botocore SSO credentials from entering logs

**Files:**
- Modify: `tests/unit/test_logging_setup.py`
- Modify: `src/agent_guardian/logging_setup.py`

**Interfaces:**
- Consumes: stdlib `logging.LogRecord` messages and the existing `_RedactingFilter`.
- Produces: `redact_secrets(text: str) -> str` that masks AWS credential shapes; `configure_logging()` that pins the `botocore` hierarchy at `WARNING` or above.

- [x] **Step 1: Add synthetic AWS credential fixtures and failing redaction tests**

Add to `tests/unit/test_logging_setup.py`:

```python
_AWS_ACCESS_KEY = "ASIAABCDEFGHIJKLMNOP"
_AWS_SECRET_KEY = "aws-secret-example-value-1234567890"
_AWS_SESSION_TOKEN = "aws-session-token-example-value-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_AWS_SSO_RESPONSE = (
    'Response body: b\'{"roleCredentials": {'
    f'"accessKeyId": "{_AWS_ACCESS_KEY}", '
    f'"secretAccessKey": "{_AWS_SECRET_KEY}", '
    f'"sessionToken": "{_AWS_SESSION_TOKEN}", '
    '"expiration": 1784303417000}}\''
)


@pytest.mark.parametrize(
    "message",
    [
        _AWS_SSO_RESPONSE,
        f"Authorization: AWS4-HMAC-SHA256 Credential={_AWS_ACCESS_KEY}/scope, "
        "SignedHeaders=host;x-amz-date, Signature=abcdef0123456789",
        f"X-Amz-Security-Token: {_AWS_SESSION_TOKEN}",
        f"aws_access_key_id={_AWS_ACCESS_KEY} aws_secret_access_key={_AWS_SECRET_KEY}",
    ],
)
def test_redact_secrets_masks_aws_credentials(message: str) -> None:
    redacted = logging_setup.redact_secrets(message)
    assert _AWS_ACCESS_KEY not in redacted
    assert _AWS_SECRET_KEY not in redacted
    assert _AWS_SESSION_TOKEN not in redacted
    assert "***REDACTED***" in redacted
```

- [x] **Step 2: Add failing run-log dependency-clamp and defense-in-depth tests**

Extend the autouse logger reset tuple with `"botocore"` and `"botocore.parsers"`, then add:

```python
def test_botocore_debug_is_excluded_from_run_log(tmp_path: Path) -> None:
    logging_setup.configure_logging(level="WARNING", stream=io.StringIO(), force=True)
    run_log = tmp_path / "run.log"
    handler = logging_setup.attach_run_log_file(run_log, level="DEBUG")
    try:
        logging.getLogger("botocore.parsers").debug(_AWS_SSO_RESPONSE)
        logging.getLogger("agent_guardian.test.aws").debug("guardian-debug-visible")
        handler.flush()
        text = run_log.read_text(encoding="utf-8")
        assert "guardian-debug-visible" in text
        assert "roleCredentials" not in text
        assert _AWS_ACCESS_KEY not in text
    finally:
        logging_setup.detach_run_log_file(handler)


def test_reenabled_botocore_debug_is_still_redacted(tmp_path: Path) -> None:
    logging_setup.configure_logging(level="WARNING", stream=io.StringIO(), force=True)
    run_log = tmp_path / "run.log"
    handler = logging_setup.attach_run_log_file(run_log, level="DEBUG")
    logger = logging.getLogger("botocore.parsers")
    logger.setLevel(logging.DEBUG)
    try:
        logger.debug(_AWS_SSO_RESPONSE)
        handler.flush()
        text = run_log.read_text(encoding="utf-8")
        assert "roleCredentials" in text
        assert _AWS_ACCESS_KEY not in text
        assert _AWS_SECRET_KEY not in text
        assert _AWS_SESSION_TOKEN not in text
        assert "***REDACTED***" in text
    finally:
        logging_setup.detach_run_log_file(handler)
```

- [x] **Step 3: Run the focused logging tests and verify red**

Run:

```bash
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/pytest -q \
  tests/unit/test_logging_setup.py::test_redact_secrets_masks_aws_credentials \
  tests/unit/test_logging_setup.py::test_botocore_debug_is_excluded_from_run_log \
  tests/unit/test_logging_setup.py::test_reenabled_botocore_debug_is_still_redacted
```

Expected: AWS values remain in `redact_secrets()` output, and botocore DEBUG enters `run.log` before the implementation.

- [x] **Step 4: Extend AWS redaction patterns**

Add field-preserving patterns to `_SECRET_PATTERNS` in `logging_setup.py` before the bare access-key pattern:

```python
(
    re.compile(
        r"(?i)([\"']?(?:accessKeyId|secretAccessKey|sessionToken|"
        r"aws_access_key_id|aws_secret_access_key|aws_session_token)[\"']?"
        r"\s*[:=]\s*[\"']?)[^\"'\s,}]+"
    ),
    r"\1" + _REDACTED,
),
(
    re.compile(r"(?i)(x-amz-security-token:\s*)\S+"),
    r"\1" + _REDACTED,
),
(
    re.compile(r"(?i)(authorization:\s*AWS4-HMAC-SHA256\s+).+"),
    r"\1" + _REDACTED,
),
(re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), _REDACTED),
```

Keep the existing provider API-key and bearer-token patterns unchanged.

- [x] **Step 5: Clamp botocore dependency logging**

Extend `_NOISY_DEPS` in `configure_logging()`:

```python
_NOISY_DEPS = (
    "httpx",
    "httpcore",
    "httpcore.http11",
    "httpcore.connection",
    "urllib3",
    "google_genai.models",
    "botocore",
    "botocore.parsers",
    "botocore.credentials",
)
```

Update the logging-test autouse reset fixture and noisy-dependency assertions to cover these names.

- [x] **Step 6: Run all logging and agent-I/O tests**

Run:

```bash
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/pytest -q \
  tests/unit/test_logging_setup.py \
  tests/unit/test_agent_io_logging.py \
  tests/unit/test_partial_scan_jsonl_log_handler.py
```

Expected: all tests pass; synthetic credentials are absent from every captured sink.

- [x] **Step 7: Commit the logging fix**

```bash
git add src/agent_guardian/logging_setup.py tests/unit/test_logging_setup.py
git commit -s -m "fix(logging): redact AWS session credentials"
```

---

### Task 2: Price current Bedrock inference-profile identifiers

**Files:**
- Modify: `tests/unit/test_llm_bedrock.py`
- Modify: `tests/unit/test_cost.py`
- Modify: `tests/unit/test_cost_qualifiers.py`
- Modify: `src/agent_guardian/llm/bedrock.py`
- Modify: `src/agent_guardian/cost.py`
- Modify: `src/agent_guardian/cli.py`
- Modify: `docs/reference/cli.mdx`

**Interfaces:**
- Produces: `BedrockClient.pricing_model_spec(request: LLMRequest) -> str` returning exactly one `bedrock:` prefix.
- Produces: `lookup_price()` rows for current Claude Haiku 4.5 global and geographic inference profiles.

- [x] **Step 1: Add a failing Bedrock pricing-identity test**

Add to `tests/unit/test_llm_bedrock.py`:

```python
def test_bedrock_pricing_identity_is_provider_qualified(_fake_aws_env: None) -> None:
    client = BedrockClient(region="us-east-1")
    try:
        bare = LLMRequest(
            messages=[LLMMessage(role="user", content="x")],
            model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        )
        prefixed = bare.model_copy(update={"model": f"bedrock:{bare.model}"})
        assert client.pricing_model_spec(bare) == (
            "bedrock:us.anthropic.claude-haiku-4-5-20251001-v1:0"
        )
        assert client.pricing_model_spec(prefixed) == client.pricing_model_spec(bare)
    finally:
        asyncio.run(client.aclose())
```

Add `import asyncio` to the test module.

- [x] **Step 2: Add failing global and geographic price tests**

Add to `tests/unit/test_cost_qualifiers.py`:

```python
@pytest.mark.parametrize(
    ("model", "input_rate", "output_rate"),
    [
        ("global.anthropic.claude-haiku-4-5-20251001-v1:0", 1.00, 5.00),
        ("us.anthropic.claude-haiku-4-5-20251001-v1:0", 1.10, 5.50),
        ("eu.anthropic.claude-haiku-4-5-20251001-v1:0", 1.10, 5.50),
        ("au.anthropic.claude-haiku-4-5-20251001-v1:0", 1.10, 5.50),
        ("jp.anthropic.claude-haiku-4-5-20251001-v1:0", 1.10, 5.50),
        ("anthropic.claude-haiku-4-5-20251001-v1:0", 1.10, 5.50),
        ("us.anthropic.claude-haiku-4-5-v1:0", 1.10, 5.50),
    ],
)
def test_bedrock_haiku45_inference_profile_rates(
    model: str,
    input_rate: float,
    output_rate: float,
) -> None:
    row = lookup_price(f"bedrock:{model}")
    assert row.provider == "bedrock"
    assert row.model == model
    assert row.input_per_1m == pytest.approx(input_rate)
    assert row.output_per_1m == pytest.approx(output_rate)


def test_unknown_bedrock_model_keeps_conservative_fallback() -> None:
    row = lookup_price("bedrock:vendor.future-model-v99")
    assert row.provider == "bedrock"
    assert row.input_per_1m == pytest.approx(3.00)
    assert row.output_per_1m == pytest.approx(15.00)
```

Update the table-date assertion in `tests/unit/test_cost.py` to expect `2026-07-17`.

- [x] **Step 3: Run the focused pricing tests and verify red**

Run:

```bash
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/pytest -q \
  tests/unit/test_llm_bedrock.py::test_bedrock_pricing_identity_is_provider_qualified \
  tests/unit/test_cost_qualifiers.py::test_bedrock_haiku45_inference_profile_rates \
  tests/unit/test_cost_qualifiers.py::test_unknown_bedrock_model_keeps_conservative_fallback
```

Expected: provider identity is bare and current IDs resolve to the `$3/$15` fallback.

- [x] **Step 4: Preserve provider identity in `BedrockClient`**

Add to `BedrockClient`:

```python
def pricing_model_spec(self, request: LLMRequest) -> str:
    """Return the provider-qualified Bedrock model used for pricing."""
    model = request.model
    if model.startswith("bedrock:"):
        model = model[len("bedrock:") :]
    return f"bedrock:{model}"
```

- [x] **Step 5: Resolve the Haiku 4.5 model family by AWS identifier shape**

In `cost.py`, import `re`, set `PRICE_TABLE_AS_OF = "2026-07-17"`, and add:

```python
_BEDROCK_HAIKU_45_RE = re.compile(
    r"^(?:(global|us|eu|au|jp)\.)?"
    r"anthropic\.claude-haiku-4-5(?:-20251001)?-v1:0$"
)


def _bedrock_haiku_45_price(model: str) -> PriceRow | None:
    match = _BEDROCK_HAIKU_45_RE.fullmatch(model)
    if match is None:
        return None
    rates = (1.00, 5.00) if match.group(1) == "global" else (1.10, 5.50)
    return PriceRow("bedrock", model, *rates)
```

Inside the provider-qualified branch of `lookup_price()`, before exact table
matching:

```python
if provider == "bedrock":
    bedrock_row = _bedrock_haiku_45_price(model)
    if bedrock_row is not None:
        return bedrock_row
```

Remove stale `$0.80/$4.00` Claude Haiku 4.5 exact rows from `PRICE_TABLE` so the
family helper is the single source of truth. Preserve Sonnet and unknown-model
fallback rows.

- [x] **Step 6: Update current CLI examples**

Replace `bedrock:us.anthropic.claude-haiku-4-5-v1:0` with
`bedrock:us.anthropic.claude-haiku-4-5-20251001-v1:0` in `cli.py` help text and
`docs/reference/cli.mdx`.

- [x] **Step 7: Run Bedrock, cost, admission, and registry tests**

Run:

```bash
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/pytest -q \
  tests/unit/test_llm_bedrock.py \
  tests/unit/test_cost.py \
  tests/unit/test_cost_qualifiers.py \
  tests/unit/test_budget_ledger.py \
  tests/unit/test_llm_registry.py
```

Expected: all tests pass; current US ID resolves to `$1.10/$5.50` and global to `$1/$5`.

- [x] **Step 8: Commit the pricing fix**

```bash
git add \
  src/agent_guardian/llm/bedrock.py \
  src/agent_guardian/cost.py \
  src/agent_guardian/cli.py \
  tests/unit/test_llm_bedrock.py \
  tests/unit/test_cost.py \
  tests/unit/test_cost_qualifiers.py \
  docs/reference/cli.mdx
git commit -s -m "fix(cost): price current Bedrock inference profiles"
```

---

### Task 3: Surface conservative cancellation spend consistently

**Files:**
- Modify: `tests/unit/test_budget_cap.py`
- Modify: `tests/unit/reports/test_postscan_accounting.py`
- Modify: `src/agent_guardian/core/swarm.py`
- Modify: `src/agent_guardian/reports/postscan.py`

**Interfaces:**
- Produces: `SwarmCommander._live_cost_usd()` as the maximum of observed-response cost and committed ledger spend.
- Produces: `_build_budget_report(*, spent_usd: float | None = None) -> BudgetReport` so final report construction can use the identical cost baseline.
- Produces: `fold_postscan_usage()` with one baseline for both cost fields.

- [x] **Step 1: Add a failing ledger-only final-report regression**

Add to `tests/unit/test_budget_cap.py`:

```python
@pytest.mark.asyncio
async def test_cancelled_request_reservation_reaches_live_and_final_cost_without_tokens() -> None:
    swarm = _swarm(usd_cap=1.0)
    assert swarm._budget_ledger is not None
    receipt = swarm._budget_ledger.reserve("target", tokens=1_111, est_usd=0.0154321)
    swarm._budget_ledger.commit(
        receipt,
        actual_usd=receipt.est_usd,
        actual_tokens=receipt.tokens,
    )

    assert swarm._usage_rollup(include_report_fallback=False) == pytest.approx((0, 0.0))
    assert swarm._live_cost_usd() == pytest.approx(0.0154321)

    swarm._start_time = 1.0
    scan = await swarm._phase_finalise()

    assert scan.tokens_total == 0
    assert scan.cost_usd == pytest.approx(0.0154321)
    assert scan.budget is not None
    assert scan.budget.spent_usd == pytest.approx(scan.cost_usd)
```

- [x] **Step 2: Replace the separate post-scan baseline test with a failing consistency test**

Rename `test_fold_postscan_usage_uses_separate_scan_and_budget_cost_baselines`
to `test_fold_postscan_usage_reconciles_to_conservative_baseline` and assert:

```python
base = 0.020
expected = base + expected_extra
assert updated.cost_usd == pytest.approx(expected)
assert updated.budget is not None
assert updated.budget.spent_usd == pytest.approx(expected)
assert updated.budget.pct_of_cap == pytest.approx(expected / 0.05)
```

- [x] **Step 3: Run focused tests and verify red**

Run:

```bash
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/pytest -q \
  tests/unit/test_budget_cap.py::test_cancelled_request_reservation_reaches_live_and_final_cost_without_tokens \
  tests/unit/reports/test_postscan_accounting.py::test_fold_postscan_usage_reconciles_to_conservative_baseline
```

Expected: live/final cost remains zero for ledger-only spend, and post-scan cost fields diverge.

- [x] **Step 4: Add a ledger spend floor to live cost**

In `SwarmCommander` add:

```python
def _ledger_spend_floor(self) -> float:
    return self._budget_ledger.spent_usd if self._budget_ledger is not None else 0.0


def _conservative_cost_usd(self, observed_cost_usd: float) -> float:
    return max(observed_cost_usd, self._ledger_spend_floor())
```

Change `_live_cost_usd()` to:

```python
def _live_cost_usd(self) -> float:
    """Return live observed spend with a floor for unknown dispatched calls."""
    observed = self._usage_rollup(include_report_fallback=False)[1]
    return self._conservative_cost_usd(observed)
```

- [x] **Step 5: Use one final report baseline**

Change `_build_budget_report` to accept an optional override:

```python
def _build_budget_report(self, *, spent_usd: float | None = None) -> BudgetReport:
    cap = self.config.usd_cap
    spent = self._live_cost_usd() if spent_usd is None else spent_usd
    pct = (spent / cap) if (cap is not None and cap > 0) else None
    return BudgetReport(
        cap_usd=cap,
        spent_usd=spent,
        pct_of_cap=pct,
        soft_stop_fraction=self.config.budget_soft_stop_fraction,
        finalise_truncated=self._finalise_truncated,
    )
```

In `_phase_finalise()`, replace the current cost calculation with:

```python
tokens_total, unrounded_observed_cost = self._usage_rollup(include_report_fallback=True)
rounded_observed_cost = round(unrounded_observed_cost, 4)
cost_usd = self._conservative_cost_usd(rounded_observed_cost)
```

Pass the exact same value into the scan:

```python
budget=self._build_budget_report(spent_usd=cost_usd),
```

This retains uncapped four-decimal behavior, retains the existing conservative
round-up when rounding increases observed cost, and never rounds a larger
ledger-only reservation down.

- [x] **Step 6: Reconcile post-scan fields**

Change `fold_postscan_usage()` to:

```python
extra_cost = tokens_to_usd(
    model_spec,
    counter.prompt_tokens,
    counter.completion_tokens,
)
budget = scan.budget
base_cost = scan.cost_usd
if budget is not None:
    base_cost = max(base_cost, budget.spent_usd)
cost_usd = base_cost + extra_cost
if budget is not None:
    pct_of_cap = cost_usd / budget.cap_usd if budget.cap_usd else None
    budget = budget.model_copy(
        update={"spent_usd": cost_usd, "pct_of_cap": pct_of_cap}
    )
```

Preserve immutable `model_copy()` behavior and successful summary token folding.

- [x] **Step 7: Run budget, prompt-target, and post-scan tests**

Run:

```bash
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/pytest -q \
  tests/unit/test_budget_ledger.py \
  tests/unit/test_budget_cap.py \
  tests/unit/test_prompt_target_accounting.py \
  tests/unit/reports/test_postscan_accounting.py \
  tests/unit/test_cli.py
```

Expected: all tests pass; cancellation contributes dollars but zero tokens, and final cost fields agree.

- [x] **Step 8: Commit the accounting fix**

```bash
git add \
  src/agent_guardian/core/swarm.py \
  src/agent_guardian/reports/postscan.py \
  tests/unit/test_budget_cap.py \
  tests/unit/reports/test_postscan_accounting.py
git commit -s -m "fix(budget): preserve unknown Bedrock spend"
```

---

### Task 4: Run complete and live AWS release verification

**Files:**
- Create ignored report: `.superpowers/sdd/task-aws-live-rerun-report.md`
- Update after success: `docs/superpowers/plans/2026-07-17-aws-bedrock-release-hardening.md`

**Interfaces:**
- Consumes: signed implementation commits from Tasks 1-3 and AWS SSO profile `ag-dev`.
- Produces: fresh automated and live evidence for a final release verdict.

- [x] **Step 1: Run static, type, repository, and package gates**

Run:

```bash
/Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/ruff check src tests
/Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/ruff format --check src tests
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/mypy src
git diff --check main...HEAD
pre-commit run --from-ref main --to-ref HEAD
uv build
```

Expected: every command exits 0.

- [x] **Step 2: Run the complete suite**

```bash
PYTHONPATH=src /Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/pytest -q
```

Expected: zero failures; only documented skips and existing deprecation warnings.

- [x] **Step 3: Perform safe AWS credential readiness checks**

Use `AWS_PROFILE=ag-dev` and `AWS_REGION=us-east-1`. Redirect all STS identity
output and access tokens to `/dev/null`. If SSO is expired, run the standard
`aws sso login --profile ag-dev` flow. Print only exit state, region, and
credential method.

- [x] **Step 4: Run one direct Bedrock exact-response smoke**

Use `BedrockClient(region="us-east-1")`, model
`us.anthropic.claude-haiku-4-5-20251001-v1:0`, temperature 0, and a fixed
sentinel instruction. Print only provider, equality state, and numeric usage.
Do not print prompt, response, account, role, headers, or credentials.

- [x] **Step 5: Run the `$0.02` hard-cap scan**

Run the same bounded command shape as the original AWS verification:

```bash
AWS_PROFILE=ag-dev AWS_REGION=us-east-1 \
CI=true AGENT_GUARDIAN_DISABLE_AUTO_SERVE=1 \
AGENT_GUARDIAN_DISABLE_URL_EMISSION=1 PYTHONPATH=src \
/Users/mobionix/workspace/Glacien/Guardian/agent_guardian_oss/.venv/bin/python \
  -m agent_guardian.cli scan \
  --system-prompt /tmp/agentguardian-gcp-live-prompt.txt \
  --model 'bedrock:us.anthropic.claude-haiku-4-5-20251001-v1:0' \
  --mode fast --max-turns 1 --budget-usd 0.02 \
  --budget-seconds 120 --recon-budget-seconds 30 \
  --output json --output-path /tmp/agentguardian-aws-hardcap-rerun.json \
  --no-tui --no-serve --no-open --no-publish --yes \
  --log-agent-io --log-agent-io-summary
```

Acceptance:

- process exit 0;
- reported spend is at least every completed response plus any committed
  unknown-outcome reservation and never exceeds `$0.02`;
- completed-response tokens are represented exactly once;
- no credential pattern exists in any artifact.

- [x] **Step 6: Run exactly one `$1.00` functional fallback when required**

If the hard-cap scan has zero tested attack turns, repeat it once with
`--budget-usd 1.00` and a unique output path. Do not run a second fallback.

Acceptance:

- attacker active and at least one tested probe turn;
- Bedrock request/response counts reconcile, with any unmatched request charged
  at its reservation;
- all completed provider tokens match requested report, `scan.json`, and
  `scan.raw.json` exactly;
- `cost_usd == budget.spent_usd` in all report forms;
- Haiku US geo pricing uses `$1.10/$5.50` rather than fallback;
- zero findings caused only by escaped ANSI text and zero actual ESC bytes.

- [x] **Step 7: Audit logs, manifests, and signatures**

For both scans:

- count true ERROR/CRITICAL, auth, 401/403, throttling, and provider failures;
- search console, `run.log`, events, reports, probe exports, and verifier output
  for `AKIA`, `ASIA`, SigV4 Authorization, `X-Amz-Security-Token`, populated AWS
  credential fields, bearer/API-key/private-key shapes, without printing any
  match;
- recompute every forensic manifest SHA-256 and byte count;
- verify requested reports with the raw 32-byte Ed25519 public key;
- retain only sanitized evidence under `.superpowers/sdd/`.

- [x] **Step 8: Obtain independent code review**

Review the full diff from `main...HEAD`, the focused test output, complete-suite
output, live report, and DCO trailers. Resolve every Critical or Important
finding before declaring release readiness.

- [x] **Step 9: Complete and commit the plan record**

Mark completed checkboxes only after the evidence exists, then run:

```bash
git add docs/superpowers/plans/2026-07-17-aws-bedrock-release-hardening.md
git commit -s -m "docs: record AWS Bedrock release verification"
```

Do not stage the pre-existing modified GCP plan unless its own outstanding live
verification checkbox is intentionally completed with current evidence.
