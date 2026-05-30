# CLI reference

**TL;DR.** Every `agent-guardian` sub-command, its flags, and a worked
example. For the canonical, always-up-to-date version run
`agent-guardian <command> --help` — the help output is generated from the
same source ([`cli.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

## Default agent slate

By default a scan runs **15 agents** — 1 reconnaissance + 10
[ASI-aligned specialists](../concepts/swarm.md) + 4 OWASP-LLM specialists
([fuzzing, secret-extraction, denial-of-wallet, detection-evasion](../concepts/swarm.md#owasp-llm-specialists)).
Pass `--no-owasp-llm` to suppress the OWASP-LLM agents and run the
11-agent ASI-only slate. Sources: the registry is built in
[`cli.py:2376`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)
and the OWASP-LLM specialist tuple in
[`agents/__init__.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/__init__.py).

## Global options

```text
agent-guardian [OPTIONS] COMMAND [ARGS]...
```

| Option       | Description                  |
|--------------|------------------------------|
| `--version`  | Print the version and exit.  |
| `--help`     | Show help and exit.          |

The CLI also auto-loads `.env` and `.env.local` from the current working
directory (only if the `[dev]` extra's `python-dotenv` is installed).
Existing environment variables always win — `.env` values do **not**
override real shell exports.

## `doctor`

Verify the install, detect available LLM keys, confirm the sandbox is
importable, print the state / config locations, and optionally probe
each detected provider for connectivity.

```text
agent-guardian doctor [--check-connectivity]
```

| Option                  | Default | Description                                                                                                  |
|-------------------------|---------|--------------------------------------------------------------------------------------------------------------|
| `--check-connectivity`  | off     | Probe each detected provider with a minimal request to validate the key + reach the endpoint. Costs one tiny call per provider (~0 tokens). Default off: key detection alone is zero-cost. |

## `init`

Author a new target contract YAML, then immediately pre-flight it.

```text
agent-guardian init [--out PATH] [--yes] [--from-openapi PATH] [--openapi-path PATH] [--openapi-method METHOD]
```

| Option                  | Default                | Description                                                                                                          |
|-------------------------|------------------------|----------------------------------------------------------------------------------------------------------------------|
| `--out PATH`            | `agentguardian.yaml`   | Where to write the new contract.                                                                                     |
| `--yes` / `-y`          | off                    | Non-interactive: write a minimal valid contract from defaults/flags. Useful for CI scaffolding.                      |
| `--from-openapi PATH`   | —                      | Pre-fill transport / request / response from an OpenAPI 3.1 spec (YAML or JSON) instead of probe-and-infer.          |
| `--openapi-path TEXT`   | —                      | With `--from-openapi`: the spec path (e.g. `/v1/chat`) whose operation to derive shapes from.                        |
| `--openapi-method TEXT` | `post`                 | With `--from-openapi` and `--openapi-path`: the HTTP method of the operation.                                        |

The interactive wizard (default) walks through HTTP target, auth,
response extraction, session mode, and Rules of Engagement. On success
the new contract is immediately run through pre-flight so you see
whether it is reachable.

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
Exits with the failing stage's exit code, or `0` when every stage
passes.

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

## `scan`

Run an adversarial swarm scan against a target. See [scan modes](../concepts/scan-modes.md)
for the cost/coverage trade-off and the [output formats reference](output-formats.md)
for what comes out.

```text
agent-guardian scan [TARGET] [OPTIONS]
```

### Target modes

Exactly one target mode must be specified:

| Mode | Flag                                              | Example                                                                  |
|------|---------------------------------------------------|--------------------------------------------------------------------------|
| A    | `--system-prompt PATH`                            | `--system-prompt prompt.txt`                                             |
| B    | positional dotted path                            | `agent-guardian scan my_agent:run`                                       |
| C    | `--endpoint URL`                                  | `--endpoint https://api.example.com/chat`                                |
| D    | `--framework KIND --framework-ref MODULE:ATTR`    | `--framework langgraph --framework-ref examples.langgraph.simple_chatbot:graph` |
| E    | `--contract PATH`                                 | `--contract agentguardian.yaml`                                          |

`--framework KIND` accepts one of six values: `adk`, `autogen`,
`crewai`, `langgraph`, `openai_agents`, `strands`. The registry lives in
[`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

### Options

| Option                       | Default | Description                                                                                          |
|------------------------------|---------|------------------------------------------------------------------------------------------------------|
| `--model TEXT`               | `stub`  | LLM model spec. Examples: `stub`, `openai:gpt-4o`, `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, `bedrock:us.anthropic.claude-haiku-4-5-v1:0`. |
| `--commander-model TEXT`     | —       | Override the commander-role model only.                                                              |
| `--attacker-model TEXT`      | —       | Override the attacker-role model only.                                                               |
| `--evaluator-model TEXT`     | —       | Override the evaluator-role model only.                                                              |
| `--framework-ref MODULE:ATTR`| —       | With `--framework`: dotted Python reference to the framework-native object to wrap (e.g. `my_app.graph:graph`). |
| `--no-preflight`             | off     | Skip the pre-scan reachability check for `--endpoint` mode. The default preflight POSTs an empty body twice with a 2s timeout. |
| `--tier TEXT`                | auto    | Force tier — one of `T1`, `T2`, `T3`, `T4`.                                                          |
| `--budget-usd FLOAT`         | —       | Runtime USD cap; soft-stops new attack turns at 80 % and reserves the remaining budget for the report. |
| `--fail-under INT`           | —       | Exit `1` if the final AIVSS score is below this value. Useful in CI gates. Non-authoritative scans (stub model or `--mode fast`) always count as failures here. |
| `--output TEXT`              | `json`  | Report format: `json`, `sarif`, `junit`, `md`, `pdf`.                                                |
| `--output-path PATH`         | —       | Where to write the report. Default: `~/.agentguardian/scans/<scan-id>/report.<output>`.              |
| `--no-tui`                   | off     | Disable the Rich progress panel. Use in CI / non-interactive shells.                                 |
| `--config PATH`              | auto    | Override config-file discovery (see [configuration schema](contract-schema.md)).                     |
| `--seed INT`                 | `0`     | RNG seed for determinism.                                                                            |
| `--goal TEXT`                | —       | Operator's natural-language attack goal. The commander decomposes it into per-agent briefs and the swarm synthesises goal-specific scenarios on top of the standard pass. |
| `--mode TEXT` / `-m`         | `full`  | Scan thoroughness — `fast` / `smart` / `full`. See [scan modes](../concepts/scan-modes.md).          |
| `--pov-gate`                 | off     | Re-run each finding's trigger N times and drop unreproducible ones before scoring (credibility gate). |
| `--critic`                   | off     | With `--pov-gate`, additionally score each PoV-passing finding on an LLM rubric and drop low-quality / high-false-positive findings. |
| `--bundle PATH`              | —       | Write a checksummed SARIF + PoV bundle to this directory.                                            |
| `--pretext`                  | off     | Wrap attacker payloads in a rotating legitimate-operations pretext (auditor / compliance / incident / onboarding). Tests refuse-on-framing. |
| `--indirect`                 | off     | Deliver attacker payloads via trusted-channel content (retrieved doc / tool output / email / memory / a2a) instead of a direct user ask — indirect prompt injection. |
| `--no-owasp-llm`             | off     | Suppress the OWASP-LLM specialist agents (fuzzing, secret-extraction, denial-of-wallet, detection-evasion). Default: those four DO run alongside the ten ASI specialists, raising the parallel cap from 10 to 14. |
| `--contract PATH`            | —       | Drive the scan from a target contract YAML. Mutually exclusive with the other target modes.          |
| `--otel-endpoint URL`        | env     | OTLP-HTTP endpoint (e.g. `http://localhost:4318/v1/traces`) to export OpenTelemetry GenAI spans to. Also read from `OTEL_EXPORTER_OTLP_ENDPOINT`. When `--contract` is used, the contract's `observability.otel_endpoint` takes precedence; this flag covers the non-contract scan modes. |

### Worked examples

```bash
# Offline scan -- no API key required (NON-AUTHORITATIVE; stub evaluator)
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

# CI gate -- fail the build if AIVSS < 70, emit SARIF for code-scanning
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

# Scan a compiled LangGraph object via dotted reference
agent-guardian scan \
  --framework langgraph \
  --framework-ref examples.langgraph.simple_chatbot:graph \
  --model openai:gpt-4o-mini
```

### Exit codes

| Code | Meaning                       |
|------|-------------------------------|
| `0`  | OK.                           |
| `1`  | `--fail-under` triggered, signature verification failed, or `UNANCHORED` for `verify` / `publish`. |
| `2`  | Configuration error (bad flag, missing file, malformed contract — env-var validation errors map here too). |
| `3`  | Target unreachable.           |
| `4`  | LLM provider error.           |
| `5`  | Sandbox violation.            |
| `130`| Interrupted by the user.      |

Full discussion + remediation per code: [reference/exit-codes.md](exit-codes.md).

## `list-agents`

Print the eleven specialist agents (one reconnaissance + ten
ASI-aligned attackers) with their ASI category.

```bash
agent-guardian list-agents
```

The OWASP-LLM specialists (fuzzing, secret-extraction, denial-of-wallet,
detection-evasion) are dispatched by `scan` when `--no-owasp-llm` is
NOT passed; they are not listed here because `list-agents` reports the
core ASI slate.

## `list-probes`

Print the bundled seed-probe corpus, one line per probe.

```text
agent-guardian list-probes [--asi ASI01]
```

| Option        | Description                                                          |
|---------------|----------------------------------------------------------------------|
| `--asi TEXT`  | Filter by ASI category — one of `ASI01`–`ASI10`.                     |

## `badge`

Emit an AIVSS badge — text by default, SVG with `--svg`.

```text
agent-guardian badge SCORE [--svg]
```

`SCORE` is the integer AIVSS value (0–100). The colour follows the
AIVSS band-to-colour map (see [AIVSS scoring](../concepts/aivss.md)).

Pipe the last scan's score directly into an SVG badge:

```bash
agent-guardian badge $(agent-guardian last-score --score-only) --svg > badge.svg
```

## `last-score`

Print the AIVSS score of the most recent scan recorded in
`~/.agentguardian/state.json`.

```text
agent-guardian last-score [--score-only]
```

| Option           | Description                                                                                                |
|------------------|------------------------------------------------------------------------------------------------------------|
| `--score-only`   | Emit only the integer score (no band, no prose) so it composes in a shell one-liner. Exits `1` when no scans are on record so the outer pipeline fails loudly. |

## `serve`

Start the local dashboard. See [operations / serve in production](../operations/serve.md)
for hardened deployments behind a reverse proxy.

```text
agent-guardian serve [--host TEXT] [--port INT] [--reload]
```

| Option       | Default     | Description                                  |
|--------------|-------------|----------------------------------------------|
| `--host`     | `127.0.0.1` | Bind host. Loopback by default.              |
| `--port`     | `7474`      | Bind port.                                   |
| `--reload`   | off         | Auto-reload on code changes (dev only).      |

The dashboard binds to loopback by default. Binding to a non-loopback
address prints a warning, exposes scan history (target URLs + findings)
and the telemetry-ingest endpoint to the network, and requires
`AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN` (or
`AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST=1`) to keep the ingest
write endpoint reachable. See [operations / serve in production](../operations/serve.md).

## `report`

Regenerate a report from a stored scan.

```text
agent-guardian report SCAN_ID [--output FORMAT] [--output-path PATH]
```

| Argument / Option   | Default | Description                                                                                      |
|---------------------|---------|--------------------------------------------------------------------------------------------------|
| `SCAN_ID`           | —       | Scan ID under `~/.agentguardian/scans/`.                                                         |
| `--output TEXT`     | `json`  | One of `json`, `sarif`, `junit`, `md`, `pdf`.                                                    |
| `--output-path PATH`| stdout  | Write to this file instead of stdout. Required for `--output pdf` (binary).                      |

Example — regenerate a previous scan as Markdown:

```bash
agent-guardian report cli-abc123def456 --output md
```

## `scans`

Manage stored scans.

```text
agent-guardian scans list
agent-guardian scans delete SCAN_ID
agent-guardian scans purge --older-than DURATION [--dry-run]
```

| Sub-command         | Description                                                                                       |
|---------------------|---------------------------------------------------------------------------------------------------|
| `scans list`        | List stored scans (id + mtime), most recent first.                                                |
| `scans delete`      | Delete a single stored scan directory.                                                            |
| `scans purge`       | Purge stored scans whose mtime is older than `--older-than` (e.g. `30d`, `2w`, `6m`). `--dry-run` previews. |

## `verify`

**TL;DR.** Verify HMAC-SHA256 + Ed25519 signatures on a signed JSON
report and prove who produced it. `verify` fails closed: a signature
alone proves integrity, not authenticity — you must supply a **trust
anchor** (a pinned Ed25519 public key and/or a real HMAC secret) before
the result counts as trusted.

```text
agent-guardian verify PATH [--pubkey TEXT | --pubkey-file PATH] [--secret TEXT]
```

| Option              | Description                                                                                                |
|---------------------|------------------------------------------------------------------------------------------------------------|
| `--pubkey TEXT`     | Pinned Ed25519 public key (base32, no padding). Required to anchor the Ed25519 leg.                        |
| `--pubkey-file PATH`| Read the pinned Ed25519 public key (base32) from a file instead of `--pubkey`. Takes precedence over `--pubkey`. |
| `--secret TEXT`     | Expected HMAC signing secret. Defaults to `AGENT_GUARDIAN_SIGNING_SECRET`. The public default secret is **never** accepted on verify. |

PDF reports ship a signed JSON sidecar at `<name>.json` — point
`verify` at that.

### How fail-closed works

If no `--secret` (or `AGENT_GUARDIAN_SIGNING_SECRET`) is supplied, the
HMAC leg is fail-closed: it returns `FAIL` rather than falling back to
the public default secret. This is intentional — see
[`crypto/hmac_sig.py:118-141`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/hmac_sig.py).
A `--pubkey`-only verification is still a green provenance result as
long as the Ed25519 leg passes and the trust anchor is `PINNED`. (A
follow-up planned for v1.1 will render that leg as `HMAC-SHA256:
SKIPPED (no secret)` for clarity — see [roadmap](roadmap.md).)

### Worked example — pubkey-only, fail-closed HMAC

```bash
REPORT=~/.agentguardian/scans/cli-abc123def456/report.json
PUBKEY=$(jq -r .signatures.ed25519.public_key_b32 "$REPORT")

agent-guardian verify "$REPORT" --pubkey "$PUBKEY"
# schema:       OK
# HMAC-SHA256:  FAIL
# Ed25519:      OK
# trust anchor: PINNED
```

Exit code: `0`. The Ed25519 leg validated against the pinned key
(`trust anchor: PINNED`), so provenance is proven. The HMAC leg fails
because no secret was supplied — fail-closed, not a tamper. The verify
result is trusted because at least one anchored channel passed; see
[`cli.py:1302`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)
and [`crypto/hmac_sig.py:118-141`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/crypto/hmac_sig.py).

### Worked example — both legs OK

Export the HMAC secret the report was signed with (must match the
producer-side `AGENT_GUARDIAN_SIGNING_SECRET`):

```bash
export AGENT_GUARDIAN_SIGNING_SECRET=demo

agent-guardian verify "$REPORT" --pubkey "$PUBKEY" --secret demo
# schema:       OK
# HMAC-SHA256:  OK
# Ed25519:      OK
# trust anchor: PINNED
```

Exit code: `0`. Both signature legs validate and the trust anchor is
pinned.

### Worked example — unanchored

The same report run without `--pubkey` (or `--secret`) prints
`trust anchor: UNANCHORED` and exits `1` — proof the integrity-only
path cannot be misread as authentic provenance:

```bash
agent-guardian verify "$REPORT"
# schema:       OK
# HMAC-SHA256:  FAIL
# Ed25519:      OK
# trust anchor: UNANCHORED
# provenance UNVERIFIED: no trust anchor supplied. ...
# Exit: 1
```

## `publish`

Publish a signed scan to the public AgentGuardian leaderboard.

```text
agent-guardian publish SCAN_ID [--output PATH]
```

| Argument / Option   | Description                                                                |
|---------------------|----------------------------------------------------------------------------|
| `SCAN_ID`           | Scan ID under `~/.agentguardian/scans/` or a direct path to a signed JSON. |
| `--output PATH`     | Where to write the redacted leaderboard-ready payload. Default: alongside the source scan. |

The public leaderboard endpoint is not yet deployed — today the command
verifies signatures, strips PII / transcripts, writes a redacted
payload, and prints manual-submission instructions.

## `telemetry`

Manage anonymous opt-in telemetry. See
[security / telemetry transparency](../security/telemetry.md) for the
full data contract.

```text
agent-guardian telemetry essential
agent-guardian telemetry extended
agent-guardian telemetry disable
agent-guardian telemetry status
agent-guardian telemetry reset
agent-guardian telemetry show
agent-guardian telemetry enable   # legacy alias for `extended` (v1.0rc1 compat)
```

| Sub-command | Description                                                                                  |
|-------------|----------------------------------------------------------------------------------------------|
| `essential` | Operational counts only (the default tier).                                                  |
| `extended`  | Essential counts plus environment fingerprint.                                               |
| `disable`   | Disable telemetry. Emits a `forget` event so the collector drops your install id.            |
| `status`    | Show the current telemetry tier and local buffer depth.                                      |
| `reset`     | Clear consent + delete install id + purge pending events. Re-asks on the next scan.          |
| `show`      | Print the full list of fields telemetry would send if enabled.                               |
| `enable`    | Legacy alias for `extended` (v1.0rc1 compatibility).                                         |

## `version`

Print the installed `agent-guardian` version and exit.

```bash
agent-guardian version
```

Equivalent to `agent-guardian --version`.
