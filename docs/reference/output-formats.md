# Output formats

**TL;DR.** Every scan can emit five report formats — `json` (canonical,
signable), `sarif` (GitHub code-scanning), `junit` (CI test reporters),
`md` (PR descriptions), `pdf` (forensic). Pick with `--output`. Default
is `json`. Per-finding text is PII- and credential-redacted on every
format unless you set `output.redact_pii: false`.

| Format     | Flag             | When to use                                                                |
|------------|------------------|----------------------------------------------------------------------------|
| **JSON**   | `--output json`  | Machine-readable evidence pack. The canonical, signable format.            |
| **SARIF**  | `--output sarif` | GitHub code-scanning, Azure DevOps, security dashboards.                   |
| **JUnit**  | `--output junit` | CI test reporters — see [GitHub Actions](../how-to/integrate-github-actions.md), [GitLab CI](../how-to/integrate-gitlab-ci.md), [Jenkins](../how-to/integrate-jenkins.md). |
| **Markdown** | `--output md`  | Human-readable report — drop into a PR description or wiki.                |
| **PDF**    | `--output pdf`   | Signed forensic bundle. Requires `[full]` (WeasyPrint) or `[pdf-fallback]` (ReportLab). |

Default path: `~/.agentguardian/scans/<scan-id>/report.<format>` unless
you pass `--output-path`.

## Where reports land

After every scan, `agent-guardian` writes both the chosen report **and**
the raw `Scan` model dump:

```text
~/.agentguardian/scans/<scan-id>/
├── scan.json         # raw Scan model dump (reconstructible — used by `report` command)
└── report.<format>   # chosen output format
```

The `scan.json` is what lets you regenerate a different format later
without re-running the swarm:

```bash
agent-guardian report cli-abc123def456 --output sarif
```

## JSON

The canonical evidence pack. Schema identifier is
`agentguardian-scan-v1` ([`json_report.py:52`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/json_report.py))
and stamped into every emitted JSON as `schema`. Top-level keys
([`json_report.py:106-121`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/json_report.py)):

| Key                       | Type                                            | What it carries                                                                                              |
|---------------------------|-------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| `schema`                  | string                                          | Always `agentguardian-scan-v1`.                                                                              |
| `scan_id`                 | string                                          | CLI-generated ID (`cli-<12-hex>`).                                                                           |
| `package_version`         | string                                          | `agent-guardian` version that ran the scan.                                                                  |
| `probe_library_version`   | string                                          | Bundled seed-probe corpus version (e.g. `2026.05`).                                                          |
| `aivss_formula_version`   | string                                          | AIVSS scorer version (e.g. `aivss-v1`).                                                                      |
| `target`                  | object                                          | `mode`, `ref`, `inferred_goal`, `profile_source`.                                                            |
| `tier`                    | string                                          | `T1`–`T4`.                                                                                                   |
| `aivss`                   | int (0–100)                                     | Overall AIVSS score.                                                                                         |
| `band`                    | string                                          | `excellent` / `good` / `moderate` / `at_risk` / `critical` / `not_evaluated`.                                |
| `sub_scores`              | object (string → float)                         | Per-sub-score values (`prompt_injection_resistance`, `tool_scope_safety`, …).                                |
| `asi_scores`              | object (`ASI01`–`ASI10` → float)                | Per-ASI scores (0–100, **floats**, NOT finding counts).                                                      |
| `findings_summary`        | object                                          | Counts by severity band.                                                                                     |
| `coverage`                | object                                          | Reconstructed from on-disk `memory.jsonl` — agents fired, probes attempted, ASI / CSA / MITRE categories hit. |
| `findings`                | array of objects                                | Per-finding records (redacted at emit time).                                                                 |
| `duration_seconds`        | float                                           | Wall-clock duration.                                                                                         |
| `cost_usd`                | float                                           | Real spend across LLM calls.                                                                                 |
| `tokens_total`            | int                                             | Total tokens consumed.                                                                                       |
| `mode`                    | string                                          | `fast` / `smart` / `full`.                                                                                   |
| `stopped_reason`          | string                                          | Why the scan ended (`finished`, `budget`, `wall_clock`, `cancelled`, …).                                     |
| `budget`                  | object \| null                                  | `cap_usd`, `spent_usd`, `pct_of_cap`, `soft_stop_fraction`, `finalise_truncated`.                            |
| `completeness`            | object \| null                                  | `agents_planned`, `agents_completed`, `turns_planned`, `turns_used`, `pct`.                                  |
| `engine`                  | object \| null                                  | Provenance — `commander_model`, `attacker_model`, `evaluator_model`.                                         |
| `evaluation_mode`         | string                                          | `live` (real evaluator LLM) or `stub` (offline; means `band=not_evaluated`).                                 |
| `scoring_valid`           | bool                                            | Whether the numeric AIVSS is authoritative. `false` for stub runs.                                           |
| `mode_authoritative`      | bool                                            | Whether the scan mode was exhaustive (`full`) vs early-stop (`smart`/`fast`).                                |
| `created_at`              | string (ISO 8601)                               | Scan start timestamp.                                                                                        |
| `audit`                   | object (only when `--contract` was used)        | RoE / contract provenance (`contract_sha256`, `authorization_ref`, `suppressed_tool_attempts`, …).           |
| `signatures`              | object (when `output.sign_evidence: true`)      | `{ "hmac_sha256": {...}, "ed25519": {...} }`. See [signing](#signing).                                       |

### Canonical sample

A real `--model stub --mode fast` scan emits this. Reproduce with:

```bash
agent-guardian scan --system-prompt prompt.txt \
  --model stub --mode fast --no-tui --seed 42 \
  --output json --output-path sample.json
```

```json
--8<-- "_assets/sample-scan.json"
```

Per-finding `summary` / `description` / `trigger_prompt` /
`transcript_ref` / `evidence` strings pass through `redact_finding` at
emit time (unless `output.redact_pii: false`). See
[`json_report.py:7-17`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/json_report.py).

## SARIF

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
— Static Analysis Results Interchange Format. Each AgentGuardian
finding becomes a SARIF `result`; each probe ID becomes a SARIF `rule`
on `runs[0].tool.driver.rules`. The emitter validates against the
bundled `sarif-2.1.0.schema.json` before returning ([`sarif.py:75-91`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py))
— a malformed payload raises `ReportError`. Contract tests:
[`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py).

When the scan was driven by `--contract`, the contract provenance
(`contract_sha256`, `contract_version`, `authorization_ref`,
suppressed-tool counts, etc.) is mirrored onto
`runs[0].properties` and the per-mode invocation onto
`runs[0].invocations`. Source: [`sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py).

Severity mapping (`finding.severity` → SARIF `level`):

| AgentGuardian severity | SARIF `level` |
|------------------------|---------------|
| `critical`             | `error`       |
| `high`                 | `error`       |
| `medium`               | `warning`     |
| `low`                  | `note`        |

```bash
agent-guardian scan --system-prompt prompt.txt \
  --model openai:gpt-4o \
  --output sarif \
  --output-path agentguardian.sarif
```

Upload via GitHub Actions' [`github/codeql-action/upload-sarif`](../how-to/integrate-github-actions.md).

!!! note "informationUri quirk"

    `tool.driver.informationUri` is currently emitted as
    `https://agentguardian.ai` rather than `.io`. Tracked for fix in
    v1.1 — see [reference / roadmap](roadmap.md).

## JUnit XML

Surfaces every finding as a JUnit `<testcase>` with a `<failure>` child,
grouped one `<testsuite>` per ASI category. Every reported `Finding`
renders as a `<failure>` so a CI gate keyed on JUnit failures cannot
go green on a reported finding. Source: [`reports/junit.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/junit.py).

Contract-provenance keys (`contract_sha256`, `authorization_ref`,
`suppressed_tool_attempts`, …) are mirrored into `<testsuites>`
properties when the scan was driven by `--contract`.

```bash
agent-guardian scan --system-prompt prompt.txt \
  --output junit \
  --output-path junit-agentguardian.xml
```

CI integration recipes: [GitHub Actions](../how-to/integrate-github-actions.md),
[GitLab CI](../how-to/integrate-gitlab-ci.md),
[Jenkins](../how-to/integrate-jenkins.md).

## Markdown

Human-readable. Drop the body into a PR description, wiki page, or
post-mortem artefact. Source: [`reports/markdown.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/markdown.py).
Layout: header → summary table → per-ASI section → top-five findings
inside `<details>` blocks. Finding-supplied strings are HTML-escaped so
attacker-reflected markup renders inert.

```bash
agent-guardian scan --system-prompt prompt.txt --output md > scan.md
```

## PDF

Signed forensic bundle. Requires a PDF engine:

- `pip install 'agent-guardian[full]'` — WeasyPrint (preferred;
  full-fidelity layout, real typography, embedded Inter +
  JetBrains Mono fonts via the bundled WOFF2 files). Depends on
  native libraries `libpango` / `libpangoft2`. If WeasyPrint imports
  fail at runtime due to missing native libs, see
  [FAQ — WeasyPrint install fails](../faq/index.md).
- `pip install 'agent-guardian[pdf-fallback]'` — ReportLab (lighter dep
  tree, single-page summary layout).

Engine selection order ([`pdf.py:8-13`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/pdf.py)):

1. `engine=` kwarg.
2. `AGENT_GUARDIAN_PDF_ENGINE` env var (`weasyprint` or `reportlab`).
3. WeasyPrint if importable, otherwise ReportLab.

If neither is available, the CLI raises `PdfFeatureUnavailable` and
exits with `EXIT_CONFIG` (2). Check `agent_guardian.available_pdf_engines()`
to inspect what's resolvable.

```bash
agent-guardian scan --system-prompt prompt.txt \
  --output pdf \
  --output-path report.pdf
```

PDF reports ship a signed JSON sidecar at `<name>.json` — that sidecar
is what you pass to [`verify`](cli.md#verify).

## Signing

When `output.sign_evidence: true` (the default), every JSON report
carries two signature blocks under `signatures`:

- **HMAC-SHA256** — symmetric. Derived from a project-wide signing
  secret (`AGENT_GUARDIAN_SIGNING_SECRET`) via PBKDF2. Fail-closed on
  verify: if no secret is supplied, this leg returns `FAIL` rather than
  trusting the public default. Source:
  [`crypto/hmac_sig.py:118-141`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/hmac_sig.py).
- **Ed25519** — asymmetric. Private key auto-generated on first use
  under `~/.agentguardian/keys/`; the public key is what consumers of
  your reports pin via `agent-guardian verify --pubkey`.

Verify a report:

```bash
agent-guardian verify path/to/report.json --pubkey <base32>
```

See [reference / cli — verify](cli.md#verify) for fail-closed semantics
and worked examples, and [security / signing & verification](../security/signing.md)
for the trust model.

`publish` reuses the same check and refuses to publish unsigned or
tampered reports.

## Multiple formats in one run

The CLI's `--output` accepts a single format. To emit multiple formats
from one scan, set `output.formats` in `.agentguardian.yaml`:

```yaml
output:
  formats: [json, sarif, junit, md]
```

Or re-emit from the stored `scan.json`:

```bash
for fmt in json sarif junit md; do
  agent-guardian report cli-abc123def456 --output "$fmt" \
    --output-path "report.$fmt"
done
```
