# Output Formats

Every scan can emit its report in five formats. Pick by use case:

| Format     | Flag             | When to use                                                                |
|------------|------------------|----------------------------------------------------------------------------|
| **JSON**   | `--output json`  | Machine-readable evidence pack. The canonical, signable format.            |
| **SARIF**  | `--output sarif` | GitHub code-scanning, Azure DevOps, security dashboards.                   |
| **JUnit**  | `--output junit` | CI test reporters (Jenkins, GitLab, CircleCI test tabs).                   |
| **Markdown** | `--output md`  | Human-readable report — drop into a PR description or wiki.                |
| **PDF**    | `--output pdf`   | Signed forensic bundle. Requires `[full]` (WeasyPrint) or `[pdf-fallback]` (ReportLab). |

Default: `json`. The default path is `~/.agentguardian/scans/<scan-id>/report.<format>` unless you pass `--output-path`.

## Where reports land

After every scan, `agent-guardian` writes both the chosen report **and** the raw Pydantic dump:

```text
~/.agentguardian/scans/<scan-id>/
├── scan.json         # raw Scan model dump (reconstructible — used by `report` command)
└── report.<format>   # chosen output format
```

The `scan.json` is what lets you regenerate a different format later without re-running the swarm:

```bash
agent-guardian report cli-abc123def456 --output sarif
```

## JSON

The canonical evidence pack. Schema version is exposed at `agent_guardian.SCHEMA_VERSION` and stamped into every emitted JSON. Top-level shape:

```jsonc
{
  "schema_version": "...",
  "scan_id": "cli-abc123def456",
  "aivss": 87,
  "band": "high",
  "tier": "T2",
  "findings": [ ... ],
  "per_asi": { "ASI01": 3, "ASI02": 0, ... },
  "duration_seconds": 142.7,
  "signatures": {                 // present when sign_evidence: true
    "hmac_sha256": { ... },
    "ed25519":     { ... }
  }
}
```

Per-finding `summary` strings are passed through `PiiRedactor` at emit time (unless you set `output.redact_pii: false`).

## SARIF

[SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — Static Analysis Results Interchange Format. Each AgentGuardian finding becomes a SARIF `result` with the ASI category as the rule ID. Suitable for upload via GitHub's `github/codeql-action/upload-sarif` action.

```bash
agent-guardian scan --system-prompt prompt.txt \
  --model openai:gpt-4o \
  --output sarif \
  --output-path agentguardian.sarif
```

## JUnit XML

Surfaces every finding as a JUnit `<testcase>`. CI test reporters render the per-finding stack so you can browse from your PR's test tab.

```bash
agent-guardian scan --system-prompt prompt.txt \
  --output junit \
  --output-path junit-agentguardian.xml
```

## Markdown

Human-readable. Use as a PR description body, wiki page, or post-mortem artifact.

```bash
agent-guardian scan --system-prompt prompt.txt --output md > scan.md
```

## PDF

Signed forensic bundle. Requires a PDF engine:

- `pip install 'agent-guardian[full]'` — WeasyPrint (preferred; embedded Inter + JetBrains Mono fonts via the bundled WOFF2 files).
- `pip install 'agent-guardian[pdf-fallback]'` — ReportLab (lighter dep tree, simpler layout).

If no engine is installed, the CLI raises `PdfFeatureUnavailable` and exits with `EXIT_CONFIG`. Check `agent_guardian.available_pdf_engines()` to inspect what's resolvable.

```bash
agent-guardian scan --system-prompt prompt.txt \
  --output pdf \
  --output-path report.pdf
```

PDF reports ship a signed JSON sidecar at `<name>.json` — that sidecar is what you pass to [`verify`](../cli.md#verify).

## Signing

When `output.sign_evidence: true` (the default), every JSON report carries two signature blocks:

- **HMAC-SHA256** — symmetric. Derived from a project-wide signing secret via PBKDF2.
- **Ed25519** — asymmetric. The private key is stored under `~/.agentguardian/keys/` (auto-generated on first use); the public key is what consumers of your reports need to verify.

Verify a report:

```bash
agent-guardian verify path/to/report.json
```

`verify` checks the schema, recomputes both signatures, and exits non-zero on any failure. `publish` reuses the same check and refuses to publish unsigned or tampered reports.

## Multiple formats in one run

The CLI's `--output` accepts a single format. To emit multiple formats from one scan, set `output.formats` in `.agentguardian.yaml`:

```yaml
output:
  formats: [json, sarif, junit, md]
```

Or re-emit from the stored `scan.json`:

```bash
for fmt in json sarif junit md; do
  agent-guardian report cli-abc123def456 --output "$fmt" > "report.$fmt"
done
```
