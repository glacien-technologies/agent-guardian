# CLI Reference

The `agent-guardian` CLI is the primary way to drive a scan. This page documents every command and flag. For the canonical, always-up-to-date version, run `agent-guardian <command> --help`.

## Global options

```text
agent-guardian [OPTIONS] COMMAND [ARGS]...
```

| Option       | Description                  |
|--------------|------------------------------|
| `--version`  | Print the version and exit.  |
| `--help`     | Show help and exit.          |

The CLI also auto-loads `.env` and `.env.local` from the current working directory (only if the `[dev]` extra's `python-dotenv` is installed). Existing environment variables always win — `.env` values do **not** override real shell exports.

---

## `init`

Author a new target contract YAML, then immediately pre-flight it.

```text
agent-guardian init [--out PATH] [--yes] [--from-openapi PATH] [--openapi-path PATH] [--openapi-method METHOD]
```

| Option                | Default                | Description                                                                                                          |
|-----------------------|------------------------|----------------------------------------------------------------------------------------------------------------------|
| `--out PATH`          | `agentguardian.yaml`   | Where to write the new contract.                                                                                     |
| `--yes` / `-y`        | off                    | Non-interactive: write a minimal valid contract from defaults/flags. Useful for CI scaffolding.                      |
| `--from-openapi PATH` | —                      | Pre-fill transport / request / response from an OpenAPI 3.1 spec (YAML or JSON) instead of probe-and-infer.          |
| `--openapi-path TEXT` | —                      | With `--from-openapi`: the spec path (e.g. `/v1/chat`) whose operation to derive shapes from.                        |
| `--openapi-method TEXT` | `post`               | With `--from-openapi` and `--openapi-path`: the HTTP method of the operation.                                        |

The interactive wizard (default) walks you through HTTP target, auth,
response extraction, session mode, and Rules of Engagement. On success
the new contract is immediately run through pre-flight so you see
whether it is reachable.

---

## `validate`

Run the payload-free pre-flight against a contract.

```text
agent-guardian validate [CONTRACT] [--json] [--stage STAGE]
```

| Option / Argument | Default               | Description                                                            |
|-------------------|-----------------------|------------------------------------------------------------------------|
| `CONTRACT`        | `agentguardian.yaml`  | Path to the contract YAML to validate.                                 |
| `--json`          | off                   | Emit the pre-flight report as JSON instead of human-readable text.     |
| `--stage TEXT`    | —                     | Only print this single stage's result (by name).                       |

Walks the seven non-adversarial stages (resolve, connect, probe,
round-trip, session, capability, RoE) and stops at the first failure.
Exits with the failing stage's exit code, or `EXIT_OK` (`0`) when
every stage passes.

---

## `contract`

Work with target contracts.

```text
agent-guardian contract schema --out PATH
agent-guardian contract migrate FILE [--write]
```

| Sub-command             | Description                                                                                  |
|-------------------------|----------------------------------------------------------------------------------------------|
| `contract schema --out` | Write the contract JSON Schema to a file (e.g. for editor autocompletion).                   |
| `contract migrate FILE` | Migrate a contract toward the current schema version. Use `--write` to update FILE in place. |

---

## `scan`

Run an adversarial swarm scan against a target.

```text
agent-guardian scan [TARGET] [OPTIONS]
```

Exactly one target mode must be specified:

| Mode | Flag                          | Example                                     |
|------|-------------------------------|---------------------------------------------|
| A    | `--system-prompt PATH`        | `--system-prompt prompt.txt`                |
| B    | positional dotted path        | `agent-guardian scan my_agent:run`          |
| C    | `--endpoint URL`              | `--endpoint https://api.example.com/chat`   |
| D    | `--framework KIND`            | `--framework langgraph` *(adapter classes shipped; CLI dispatch lands in v1.1)* |

### Options

| Option                       | Default | Description                                                                                          |
|------------------------------|---------|------------------------------------------------------------------------------------------------------|
| `--model TEXT`               | `stub`  | LLM model spec. Examples: `stub`, `openai:gpt-4o`, `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, `bedrock:us.anthropic.claude-haiku-4-5-v1:0`. |
| `--commander-model TEXT`     | —       | Override the commander-role model only.                                                              |
| `--attacker-model TEXT`      | —       | Override the attacker-role model only.                                                               |
| `--evaluator-model TEXT`     | —       | Override the evaluator-role model only.                                                              |
| `--tier TEXT`                | auto    | Force tier — one of `T1`, `T2`, `T3`, `T4`.                                                          |
| `--budget-usd FLOAT`         | —       | Runtime USD cap; soft-stops new attack turns at 80 % and reserves the remaining budget for the report. |
| `--fail-under INT`           | —       | Exit `1` if the final AIVSS score is below this value. Useful in CI gates.                           |
| `--output TEXT`              | `json`  | Report format: `json`, `sarif`, `junit`, `md`, `pdf`.                                                |
| `--output-path PATH`         | —       | Where to write the report. Default: `~/.agentguardian/scans/<scan-id>/report.<output>`.              |
| `--no-tui`                   | off     | Disable the Rich progress panel. Use in CI / non-interactive shells.                                 |
| `--config PATH`              | auto    | Override config-file discovery (see [Configuration](guide/configuration.md)).                        |
| `--seed INT`                 | `0`     | RNG seed for determinism.                                                                            |
| `--goal TEXT`                | —       | Operator's natural-language attack goal. The Commander decomposes it into per-agent briefs and the swarm synthesises goal-specific scenarios on top of the standard pass. |
| `--mode TEXT` / `-m`         | `full`  | Scan thoroughness — `fast` / `smart` / `full`. See [Scan modes](concepts/scan-modes.md).             |
| `--pov-gate`                 | off     | Re-run each finding's trigger N times and drop unreproducible ones before scoring (credibility gate).|
| `--critic`                   | off     | With `--pov-gate`, additionally score each PoV-passing finding on an LLM rubric and drop low-quality / high-false-positive findings. |
| `--bundle PATH`              | —       | Write a checksummed SARIF+PoV bundle to this directory.                                              |
| `--pretext`                  | off     | Wrap attacker payloads in a rotating legitimate-operations pretext (auditor / compliance / incident / onboarding). Tests refuse-on-framing. |
| `--indirect`                 | off     | Deliver attacker payloads via trusted-channel content (retrieved doc / tool output / email / memory / a2a) instead of a direct user ask — indirect prompt injection. |
| `--owasp-llm`                | off     | Additionally dispatch the OWASP-LLM specialist agents (fuzzing, secret-extraction, denial-of-wallet, detection-evasion). |
| `--contract PATH`            | —       | Drive the scan from a target contract YAML. Mutually exclusive with the other target modes.          |
| `--otel-endpoint URL`        | env     | OTLP-HTTP endpoint (e.g. `http://localhost:4318/v1/traces`) to export OpenTelemetry GenAI spans to. Also read from `OTEL_EXPORTER_OTLP_ENDPOINT`. When `--contract` is used, the contract's `observability.otel_endpoint` takes precedence; this flag covers the non-contract scan modes. |

### Examples

```bash
# Offline scan — no API key required
agent-guardian scan --system-prompt prompt.txt --model stub

# Real scan with OpenAI, JSON report to a custom path
agent-guardian scan --system-prompt prompt.txt \
  --model openai:gpt-4o \
  --output json \
  --output-path ./report.json

# Hybrid: cheap attacker model, expensive evaluator
agent-guardian scan --system-prompt prompt.txt \
  --attacker-model openai:gpt-4o-mini \
  --evaluator-model anthropic:claude-opus-4-7

# CI gate — fail the build if AIVSS < 70, emit SARIF for code-scanning
agent-guardian scan --system-prompt prompt.txt \
  --model openai:gpt-4o \
  --no-tui \
  --fail-under 70 \
  --output sarif \
  --output-path agentguardian.sarif

# Scan a Python callable agent
agent-guardian scan my_module:agent_main --model anthropic:claude-haiku-4-5

# Scan a hosted HTTP endpoint
agent-guardian scan --endpoint https://api.example.com/chat --model openai:gpt-4o
```

### Exit codes

| Code | Meaning                       |
|------|-------------------------------|
| `0`  | OK.                           |
| `1`  | `--fail-under` triggered (or signature verification failed / `UNANCHORED` for `verify` / `publish`). |
| `2`  | Configuration error (bad flag, missing file, malformed contract — env-var validation errors map here too — see [Environment variables](operations/env-vars.md)). |
| `3`  | Target unreachable.           |
| `4`  | LLM provider error.           |
| `5`  | Sandbox violation.            |
| `130`| Interrupted by the user.      |

---

## `doctor`

Verify the install, detect available LLM keys, confirm the sandbox is importable, and print the state / config locations.

```bash
agent-guardian doctor
```

---

## `list-agents`

Print the eleven specialist agents (one reconnaissance + ten ASI-aligned attackers) with their ASI category.

```bash
agent-guardian list-agents
```

---

## `list-probes`

Print the bundled seed-probe corpus, one line per probe.

```text
agent-guardian list-probes [--asi ASI01]
```

| Option        | Description                                                          |
|---------------|----------------------------------------------------------------------|
| `--asi TEXT`  | Filter by ASI category — one of `ASI01`–`ASI10`.                     |

---

## `badge`

Emit an AIVSS badge — text by default, SVG with `--svg`.

```text
agent-guardian badge SCORE [--svg]
```

`SCORE` is the integer AIVSS value (0–100). The colour follows the AIVSS band-to-colour map (see [AIVSS formula — severity bands](aivss-formula.md#severity-bands)).

Example — pipe the last scan's score directly into an SVG badge:

```bash
agent-guardian badge $(agent-guardian last-score) --svg > badge.svg
```

---

## `last-score`

Print the AIVSS score of the most recent scan recorded in `~/.agentguardian/state.json`.

```bash
agent-guardian last-score
```

---

## `serve`

Start the local dashboard.

```text
agent-guardian serve [--host TEXT] [--port INT] [--reload]
```

| Option       | Default     | Description                                  |
|--------------|-------------|----------------------------------------------|
| `--host`     | `127.0.0.1` | Bind host. Loopback by default.              |
| `--port`     | `7474`      | Bind port.                                   |
| `--reload`   | off         | Auto-reload on code changes (dev only).      |

The dashboard binds to loopback by default. Bind to `0.0.0.0` only when you understand the network exposure implications.

---

## `report`

Regenerate a report from a stored scan.

```text
agent-guardian report SCAN_ID [--output FORMAT]
```

| Argument / Option   | Default | Description                                        |
|---------------------|---------|----------------------------------------------------|
| `SCAN_ID`           | —       | Scan ID under `~/.agentguardian/scans/`.           |
| `--output TEXT`     | `json`  | One of `json`, `sarif`, `junit`, `md`, `pdf`.      |

Example — regenerate a previous scan as Markdown:

```bash
agent-guardian report cli-abc123def456 --output md
```

---

## `verify`

Verify HMAC-SHA256 + Ed25519 signatures on a signed JSON report.

```bash
agent-guardian verify path/to/report.json [OPTIONS]
```

| Option              | Description                                                                                                |
|---------------------|------------------------------------------------------------------------------------------------------------|
| `--pubkey TEXT`     | Pinned Ed25519 public key (base32, no padding). Required to anchor the Ed25519 leg.                        |
| `--pubkey-file PATH`| Read the pinned Ed25519 public key (base32) from a file instead of `--pubkey`. Takes precedence over `--pubkey`. |
| `--secret TEXT`     | Expected HMAC signing secret. Defaults to `AGENT_GUARDIAN_SIGNING_SECRET`. The public default secret is **never** accepted on verify. |

### Trust anchor

`verify` fails closed. A signature alone proves only that the bytes
were not tampered (integrity), not *who* signed them. To report a green
result you must supply a trust anchor — a pinned Ed25519 public key
(`--pubkey` / `--pubkey-file`) and/or a real HMAC secret (`--secret` /
`AGENT_GUARDIAN_SIGNING_SECRET`). Without an anchor the report is shown
as `trust anchor: UNANCHORED` and the command exits **1**.

PDF reports ship a signed JSON sidecar at `<name>.json` — point
`verify` at that.

### Worked example

```bash
REPORT=~/.agentguardian/scans/cli-abc123def456/report.json
PUBKEY=$(jq -r .signatures.ed25519.public_key_b32 "$REPORT")
agent-guardian verify "$REPORT" --pubkey "$PUBKEY"
# schema:       OK
# HMAC-SHA256:  OK
# Ed25519:      OK
# trust anchor: PINNED
```

The same report run without `--pubkey` (or `--secret`) prints
`trust anchor: UNANCHORED` and exits `1` — proof the integrity-only
path cannot be misread as authentic provenance.

---

## `publish`

Publish a signed scan to the public AgentGuardian leaderboard.

```text
agent-guardian publish SCAN_ID [--output PATH]
```

| Argument / Option   | Description                                                                |
|---------------------|----------------------------------------------------------------------------|
| `SCAN_ID`           | Scan ID under `~/.agentguardian/scans/` or a direct path to a signed JSON. |
| `--output PATH`     | Where to write the redacted leaderboard-ready payload. Default: alongside the source scan. |

The public leaderboard endpoint is not yet deployed — today the command verifies signatures, strips PII / transcripts, writes a redacted payload, and prints manual-submission instructions.

---

## `telemetry`

Manage anonymous opt-out telemetry (see [Telemetry transparency](telemetry/index.md) for the full data contract).

```bash
agent-guardian telemetry enable
agent-guardian telemetry disable
agent-guardian telemetry status
```

---

## `version`

Print the installed `agent-guardian` version and exit.

```bash
agent-guardian version
```

Equivalent to `agent-guardian --version`.
