# Add to your CI pipeline

!!! tip "TL;DR"
    Fifteen minutes from "passing tests" to a signed SARIF artifact in your security dashboard. We'll wire `agent-guardian scan` into GitHub Actions with a `--fail-under` AIVSS threshold, upload SARIF to GitHub code-scanning, and verify the signed report. GitLab CI and Jenkins recipes link out to the dedicated how-to guides.

## 1. Why a CI gate

A scan you run by hand catches today's regression once. A scan you run in CI catches every regression, on every PR, without anyone remembering to. The gate has two jobs:

1. **Block** a PR whose AIVSS dropped below your floor (e.g. a refactor that gutted the input-sanitiser).
2. **Surface** every finding as a SARIF result so it appears next to the diff in your code-review tool.

For the conceptual case (what AgentGuardian protects against, and why an LLM-driven swarm catches what a static rule set can't), read [Concepts → Why AgentGuardian](../concepts/why.md).

## 2. Pick a `--fail-under` threshold

`--fail-under N` makes the CLI exit `1` (`EXIT_FAIL_UNDER`, [`cli.py:84`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L84)) when the final AIVSS is below `N`. Two extra safeties on top of the integer comparison ([`cli.py:2583-2598`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2583-L2598)):

- A **non-authoritative** scan (`scoring_valid=False`, e.g. stub backend) is **always** a gate failure — a CI gate that quietly passes on a stub run defeats its own purpose.
- A scan run in `--mode fast` or `--mode smart` is also treated as **non-authoritative for gate purposes** — those modes deliberately under-test for speed, so their numeric AIVSS is a smoke signal, not an audit. Use `--mode full` whenever a gate decision will be quoted.

Suggested thresholds, copied from [Concepts → Scan modes](../concepts/scan-modes.md#picking-a-fail-under-per-mode):

| Mode    | Suggested `--fail-under` | Use case                                                    |
| ------- | ------------------------ | ----------------------------------------------------------- |
| `fast`  | 60                       | Pre-merge smoke gate. "Did I obviously break something?"    |
| `smart` | 70                       | Iterative dev loops. Full corpus, may early-stop.           |
| `full`  | 80                       | Pre-release audit. Authoritative number for stakeholders.   |

Start at the suggested value, then tighten once you've run a few PRs and seen the natural distribution of scores on your repo.

## 3. GitHub Actions (SARIF upload)

Drop this workflow at `.github/workflows/agentguardian.yml`. It runs on every PR and on pushes to `main`, scans `prompt.txt` at the repo root, fails the build on AIVSS &lt; 70, and uploads SARIF to the **Security → Code scanning** tab of your repository.

```yaml
name: AgentGuardian scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required for upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install AgentGuardian
        run: pip install agent-guardian

      - name: Run scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          AGENT_GUARDIAN_SIGNING_SECRET: ${{ secrets.AGENT_GUARDIAN_SIGNING_SECRET }}
        run: |
          agent-guardian scan \
            --system-prompt prompt.txt \
            --model openai:gpt-4o-mini \
            --mode full \
            --no-tui \
            --fail-under 70 \
            --output sarif \
            --output-path agentguardian.sarif

      - name: Upload SARIF to GitHub code scanning
        if: always()      # upload even on a --fail-under failure
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentguardian.sarif
          category: agentguardian
```

A few flag notes:

- `--no-tui` disables the Rich progress panel ([`cli.py:2067`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2067)). Required in non-interactive shells; CI logs are unreadable otherwise.
- `--output sarif --output-path agentguardian.sarif` writes the SARIF 2.1.0 artifact ([`cli.py:2061-2066`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2061-L2066)). The emitter is in [`reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py); the schema conformance is locked down by [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py).
- `if: always()` on the upload step is **important** — when `--fail-under` trips, the scan step exits `1` and the upload would otherwise be skipped. You want the SARIF on the PR even when the gate failed.
- `AGENT_GUARDIAN_SIGNING_SECRET` keys the HMAC on the signed report. Optional — Ed25519 always signs — but recommended if you want to re-verify the artifact downstream of CI.

The SARIF will appear under **Security → Code scanning** with one alert per finding, each tagged with the ASI category as the rule ID. Existing reference at [Reference → Output formats — SARIF](../reference/output-formats.md).

## 4. Stub scan for the smoke-test variant

If you don't want to pay LLM cost on every PR and only need to confirm the CLI is wired and the artifact path is valid, run the **stub** as a smoke check:

```yaml
      - name: Smoke check (stub, never gates)
        run: |
          agent-guardian scan \
            --system-prompt prompt.txt \
            --model stub \
            --no-tui \
            --output sarif \
            --output-path agentguardian.sarif
```

Drop the `--fail-under` flag — a stub run will **always** trip it (the swarm marks `scoring_valid=False`). The SARIF is still emitted; treat it as a pipeline sanity check, not a security assessment. For the explanation see [First scan — Why the band is NOT_EVALUATED](first-scan.md#3-run-the-scan).

## 5. GitLab CI

GitLab's `Secret_Detection.gitlab-ci.yml` template feeds SARIF into the **Security & Compliance → Vulnerabilities** dashboard. The same `--output sarif --output-path` flow applies; the difference is the artifact declaration. Full recipe with a JUnit + SARIF dual-artifact pattern in [How-to → Integrate with GitLab CI](../how-to/integrate-gitlab-ci.md).

## 6. Jenkins

A Jenkins recipe with a `Jenkinsfile` snippet (declarative pipeline + the Warnings-NG plugin reading the SARIF) is at [How-to → Integrate with Jenkins](../how-to/integrate-jenkins.md).

## 7. Verify the signed report in CI

If you set `AGENT_GUARDIAN_SIGNING_SECRET` in step 3, add a verify step after the scan to prove the artifact wasn't tampered with between the scan job and a downstream consumer (e.g. an attestation upload):

```yaml
      - name: Verify signature
        env:
          AGENT_GUARDIAN_SIGNING_SECRET: ${{ secrets.AGENT_GUARDIAN_SIGNING_SECRET }}
        run: |
          REPORT="$HOME/.agentguardian/scans/$(jq -r .last_scan_id "$HOME/.agentguardian/state.json")/report.json"
          PUBKEY=$(jq -r .signatures.ed25519.public_key_b32 "$REPORT")
          agent-guardian verify "$REPORT" --pubkey "$PUBKEY"
```

Expected output (exit `0`):

```text
schema:       OK
HMAC-SHA256:  OK
Ed25519:      OK
trust anchor: PINNED
```

`HMAC-SHA256: OK` confirms the secret round-tripped through CI; `Ed25519: OK` + `trust anchor: PINNED` is the integrity + authenticity anchor. Without the secret you would see `HMAC-SHA256: FAIL` (expected, fails closed — see the [FAQ entry on `UNANCHORED`](../faq/index.md#why-does-agent-guardian-verify-print-trust-anchor-unanchored)).

## 8. Troubleshooting

If the CI run dies in an unfamiliar way, hit the symptom catalogue first: [FAQ → Troubleshooting](../faq/troubleshooting.md). The four most common CI-specific failures:

- **`EgressRefused` mid-scan** — the runner can't reach an LLM or RAG endpoint the swarm tried to probe. See [FAQ — `EgressRefused`](../faq/index.md#egressrefused).
- **`pip install 'agent-guardian[full]'` errors on `weasyprint`** — switch to `[pdf-fallback]` or skip PDF in CI. See [FAQ — WeasyPrint native deps](../faq/index.md#pip-install-agent-guardianfull-fails-on-weasyprint-native-deps).
- **`Presidio model download fails`** — pre-bake the spaCy models into your runner image or fall back to the regex `PiiRedactor`. See [FAQ — Presidio model download](../faq/index.md#presidio-model-download-fails-is-slow).
- **Gate fails on a stub run** — by design. Switch to a real `--model` for a gate; use stub only for smoke checks (step 4).

Exit code reference: [Reference → Exit codes](../reference/exit-codes.md).
