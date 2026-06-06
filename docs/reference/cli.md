# CLI reference

The canonical `agent-guardian` CLI surface, sourced from the live Typer
app in `src/agent_guardian/cli.py`. For the always-up-to-date version
run `agent-guardian <command> --help`.

Coming soon: this Markdown page is a stable redirect target for the
v1.0 IA. The fully-rendered reference lives in
[`docs/reference/cli.mdx`](./cli.mdx) and is published via the Mintlify
site at [https://docs.agentguardian.io/reference/cli](https://docs.agentguardian.io/reference/cli). This `.md` stub
exists so the v1.0 docs URL (`docs/reference/cli.md`) keeps resolving
for inbound links and so the CLI-coverage test can assert that every
flag landing in `cli.py` is named here.

## Global options

```text
agent-guardian [--version] [--help] COMMAND [ARGS]...
```

The CLI also auto-loads `.env` / `.env.local` from the current working
directory when `python-dotenv` is installed. Existing shell exports
always win.

## Commands

Every top-level command listed below resolves to a Typer command in
`src/agent_guardian/cli.py`. Run `agent-guardian <command> --help` for
the full option set.

### `version`

```text
agent-guardian version
```

Print the installed package version and exit.

### `doctor`

```text
agent-guardian doctor
```

Verify the install, detect available LLM keys, confirm the sandbox is
importable, and print state / config locations.

### `list-agents`

```text
agent-guardian list-agents
```

Print the eleven specialist agents with their ASI category.

### `list-probes`

```text
agent-guardian list-probes
```

Print the bundled seed-probe corpus, one line per probe.

### `badge`

```text
agent-guardian badge
```

Emit an AIVSS badge — text by default, SVG with `--svg`.

### `last-score`

```text
agent-guardian last-score
```

Print the AIVSS of the most recent scan in the local scan store.

### `serve`

```text
agent-guardian serve
```

Start the local FastAPI dashboard at `http://127.0.0.1:7474/`.

### `report`

```text
agent-guardian report <SCAN_ID> [--output {json|sarif|junit|md|pdf}] [--output-path PATH]
```

Regenerate a report from a stored scan in any supported output format. The
positional `<SCAN_ID>` is required — it resolves under
`~/.agentguardian/scans/<scan-id>/`. Text formats (`json` / `sarif` / `junit` /
`md`) print to stdout by default, or to `--output-path` when given. `--output
pdf` is binary and always requires `--output-path`.

### `verify`

```text
agent-guardian verify
```

Verify HMAC-SHA256 + Ed25519 signatures on a stored report.

### `calibrate`

```text
agent-guardian calibrate
```

Run the calibration harness against a target to size budgets before a
full scan.

### `publish`

```text
agent-guardian publish
```

Publish a signed scan bundle to the public AgentGuardian leaderboard.

### `validate`

```text
agent-guardian validate
```

Run the payload-free pre-flight against a target contract.

### `init`

```text
agent-guardian init
```

Author a new target contract interactively, then pre-flight it.

### `scan`

```text
agent-guardian scan
```

Run an adversarial swarm scan against a target. The full option table
follows in [Scan options](#scan-options).

### `telemetry`

```text
agent-guardian telemetry enable
agent-guardian telemetry disable
agent-guardian telemetry status
```

Opt-in usage telemetry. `agent-guardian telemetry enable` records the
consent decision; `agent-guardian telemetry status` prints the current
state.

### `contract`

```text
agent-guardian contract schema
agent-guardian contract migrate
```

Work with target contracts. `agent-guardian contract schema` writes the
contract JSON Schema to a file (or to stdout if no `--out` is given);
`agent-guardian contract migrate` upgrades older contracts to the
current shape.

### `agentdojo`

```text
agent-guardian agentdojo run
```

Run the optional AgentDojo benchmark pack against a target. Requires
the `[agentdojo]` extra.

### `comment`

```text
agent-guardian comment --platform github --fail-under 70
```

Upsert a single AgentGuardian summary comment on the current pull /
merge request. The comment is keyed by a hidden HTML marker so repeated
runs update the same comment in place instead of spamming a new one on
every push. `--platform` is `github` | `gitlab` | `bitbucket`; the
embedded gate verdict reuses the same `--fail-under` / `--max-critical`
/ `--max-high` / `--max-medium` / `--max-low` thresholds as the `scan`
gate, so the comment's green/red verdict matches the CI exit code. Pass
`--dry-run` to print the rendered body instead of posting it.

### `code-insights`

```text
agent-guardian code-insights --platform bitbucket
```

Publish a Bitbucket Code Insights report (a quality report plus inline
annotations) for a scan. Defaults to the newest scan under
`~/.agentguardian/scans`; pass `--scan` to target a specific scan id or
`scan.json` path, and `--dry-run` to render without posting.

## Scan options

The `scan` command exposes every knob the swarm respects. The list
below is the documented set parsed by the docs-coverage test against
`cli.py` (see `tests/docs/test_docs_cli_coverage.py`). A small number of
commands and flags are intentionally excluded from that test via the
`_SKIP_COMMAND_NAMES` and `_DOC_SKIP_FLAGS` frozensets — each entry
carries an inline rationale (operator-internal toggles, alpha shims,
or duplicate spellings).

| Flag | Purpose |
| --- | --- |
| `--system-prompt` | Override the target's system prompt for the scan. |
| `--endpoint` | Target endpoint URL (HTTP adapter targets). |
| `--framework` | Framework adapter kind (`langgraph`, `openai-agents`, …). |
| `--model` | Default model used by every swarm agent unless overridden. |
| `--commander-model` | Model used by the swarm commander. |
| `--attacker-model` | Model used by attacker / probe agents. |
| `--evaluator-model` | Model used by the evaluator / critic. |
| `--tier` | Target tier (`T1`–`T4`) — gates which probes run. |
| `--budget-usd` | Hard ceiling on spend per scan, in USD. |
| `--budget-seconds` | Hard ceiling on wall-clock per scan. |
| `--recon-budget-seconds` | Per-recon-phase wall-clock budget. |
| `--fail-under` | Exit non-zero when the AIVSS sits below this threshold. |
| `--max-critical` | Fail the gate when the CRITICAL-finding count exceeds this ceiling (AND-combined with `--fail-under`). |
| `--max-high` | Fail the gate when the HIGH-finding count exceeds this ceiling. |
| `--max-medium` | Fail the gate when the MEDIUM-finding count exceeds this ceiling. |
| `--max-low` | Fail the gate when the LOW-finding count exceeds this ceiling. |
| `--output` | One or more output formats (`json`, `sarif`, `junit`, `md`, `pdf`). |
| `--output-path` | Directory to write report artefacts to. |
| `--no-tui` | Disable the interactive TUI; emit plain logs only. |
| `--legacy-board` | Render the legacy swarm board instead of the Executive dashboard. |
| `--config` | Path to a YAML / TOML config to merge over CLI flags. |
| `--seed` | RNG seed for deterministic probe sampling and replay. |
| `--goal` | Free-form natural-language goal passed to the commander. |
| `--mode` | Scan mode (`fast` / `smart` / `full`). |
| `--pov-gate` | Enable / disable the point-of-view gate (T3+ contracts). |
| `--critic` | Enable / disable the critic agent. |
| `--bundle` | Optional named bundle of probes to run. |
| `--pretext` | Pretext to inject into multi-turn attacks. |
| `--indirect` | Enable indirect-prompt-injection probes. |
| `--contract` | Path to a target contract file. |
| `--otel-endpoint` | OTel collector endpoint to export traces to. |
| `--publish` | Publish the scan bundle to the configured dashboard. |
| `--debug` | Enable debug-level logging. |
| `--debug-format` | Debug-log format (`text` / `json`). |
| `--no-serve` | Do not auto-start the local dashboard during the scan. |
| `--serve-grace-seconds` | How long to keep the local dashboard alive after the scan finishes. |
| `--open` / `--no-open` | Open the scan-specific dashboard URL in the default browser once the scan completes. Auto-skipped under CI / SSH / non-TTY environments. |
| `--yes` | Skip interactive confirmations (CI mode). |
| `--no-plan-confirm` | Skip the plan-confirmation step. |
| `--no-plan` | Skip plan generation entirely; run the default probe order. |

For the rendered, narrative reference with worked examples, see
[`cli.mdx`](./cli.mdx).
