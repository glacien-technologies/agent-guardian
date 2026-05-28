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
| D    | `--framework KIND`            | `--framework langgraph` *(M11 — not yet wired)* |

### Options

| Option                       | Default | Description                                                                                          |
|------------------------------|---------|------------------------------------------------------------------------------------------------------|
| `--model TEXT`               | `stub`  | LLM model spec. Examples: `stub`, `openai:gpt-4o`, `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, `bedrock:us.anthropic.claude-haiku-4-5-v1:0`. |
| `--commander-model TEXT`     | —       | Override the commander-role model only.                                                              |
| `--attacker-model TEXT`      | —       | Override the attacker-role model only.                                                               |
| `--evaluator-model TEXT`     | —       | Override the evaluator-role model only.                                                              |
| `--tier TEXT`                | auto    | Force tier — one of `T1`, `T2`, `T3`, `T4`.                                                          |
| `--budget-usd FLOAT`         | —       | Cost cap; aborts before scanning if the estimate exceeds this value.                                 |
| `--fail-under INT`           | —       | Exit `1` if the final AIVSS score is below this value. Useful in CI gates.                           |
| `--output TEXT`              | `json`  | Report format: `json`, `sarif`, `junit`, `md`, `pdf`.                                                |
| `--output-path PATH`         | —       | Where to write the report. Default: `~/.agentguardian/scans/<scan-id>/report.<output>`.              |
| `--no-tui`                   | off     | Disable the Rich progress panel. Use in CI / non-interactive shells.                                 |
| `--config PATH`              | auto    | Override config-file discovery (see [Configuration](guide/configuration.md)).                        |
| `--seed INT`                 | `0`     | RNG seed for determinism.                                                                            |

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
| `1`  | `--fail-under` triggered (or signature verification failed for `verify` / `publish`). |
| `2`  | Configuration error.          |
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

`SCORE` is the integer AIVSS value (0–100). The colour follows the M2 band-to-colour map.

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

Verify HMAC-SHA256 + Ed25519 signatures on a signed JSON report (M13).

```bash
agent-guardian verify path/to/report.json
```

Exits non-zero if any signature fails. PDF reports ship a signed JSON sidecar at `<name>.json` — point `verify` at that.

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

Manage opt-in usage telemetry (M15 — currently a state-flag placeholder).

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
