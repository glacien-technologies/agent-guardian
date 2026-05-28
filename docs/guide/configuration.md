# Configuration

AgentGuardian reads settings from four sources, in descending precedence:

1. **Explicit CLI flags** — `--model`, `--tier`, `--budget-usd`, etc.
2. **Environment variables** — `AGENT_GUARDIAN_*` (API keys) and conventional ones like `OPENAI_API_KEY`.
3. **YAML config file** — discovered automatically.
4. **Defaults** — baked into the [`Config`](../api/cli.md) Pydantic model.

The Pydantic model uses `extra="forbid"` at every level — typos in your YAML surface immediately rather than being silently ignored.

## Config-file discovery

`agent-guardian` looks for a config file in this order and uses the first one it finds:

1. The path passed via `--config PATH`.
2. `.agentguardian.yaml` in the current working directory.
3. `~/.agentguardian/config.yaml` (user-level default).

If no file is found, the defaults below are used. You can start with an empty file (`touch .agentguardian.yaml`) and grow into the schema — every section is optional and falls back to its default sub-model.

## Schema

```yaml
# .agentguardian.yaml — full schema with defaults

swarm:
  commander_model: claude-haiku-4-5     # commander LLM role
  attacker_model:  gpt-4o-mini          # attacker LLM role
  evaluator_model: gpt-4o-mini          # evaluator LLM role
  max_parallel_agents: 11               # 1–11
  budget:
    wall_seconds:     900               # 15 min hard cap
    max_total_tokens: 2000000

target:
  mode:      prompt                     # one of: prompt | code | http | framework
  path:      null                       # for code mode
  endpoint:  null                       # for http mode
  framework: null                       # for framework mode (M11)
  tier:      null                       # null = auto-detect; or T1 | T2 | T3 | T4

output:
  formats:       [json]                 # any of: json | sarif | junit | md | pdf
  redact_pii:    true                   # strip PII from transcripts before emit
  sign_evidence: true                   # HMAC-SHA256 + Ed25519 signatures (M13)
  output_dir:    null                   # null = ~/.agentguardian/scans/<scan-id>/

server:
  host: 127.0.0.1                       # dashboard bind host
  port: 7474                            # dashboard bind port

telemetry:
  enabled: false                        # opt-in, off by default (M15)
```

## Section reference

### `swarm`

| Field                  | Type                | Default              | Notes                                                                 |
|------------------------|---------------------|----------------------|-----------------------------------------------------------------------|
| `commander_model`      | string              | `claude-haiku-4-5`   | Role: orchestration / checkpoint decisions.                          |
| `attacker_model`       | string              | `gpt-4o-mini`        | Role: probe generation. Cheap models work well here.                 |
| `evaluator_model`      | string              | `gpt-4o-mini`        | Role: verdict adjudication. Stronger models reduce false positives.  |
| `max_parallel_agents`  | int (1–11)          | `11`                 | Cap on concurrent ASI agents. Lower this on rate-limited tiers.      |
| `budget.wall_seconds`  | int (≥1)            | `900`                | Hard wall-clock cap. The swarm stops cleanly at this limit.          |
| `budget.max_total_tokens` | int (≥1)         | `2_000_000`          | Token budget. Donated across agents by the commander.                |

Model strings here are **bare names** — no `openai:` / `anthropic:` prefix. The provider is inferred from the prefix (or specified explicitly when needed). See [LLM Providers](../providers/index.md) for the resolution rules.

### `target`

| Field        | Type                                 | Notes                                                |
|--------------|--------------------------------------|------------------------------------------------------|
| `mode`       | `prompt` \| `code` \| `http` \| `framework` | Default `prompt`.                              |
| `path`       | string \| null                       | Only used for `code` mode.                          |
| `endpoint`   | string \| null                       | Only used for `http` mode.                          |
| `framework`  | string \| null                       | Only used for `framework` mode (M11).               |
| `tier`       | `T1`–`T4` \| null                    | `null` lets the swarm auto-detect from the fingerprint. |

### `output`

| Field           | Type           | Default | Notes                                                            |
|-----------------|----------------|---------|------------------------------------------------------------------|
| `formats`       | list of string | `[json]`| Any combination of `json`, `sarif`, `junit`, `md`, `pdf`.        |
| `redact_pii`    | bool           | `true`  | Per-finding `summary` runs through `PiiRedactor` before emit.    |
| `sign_evidence` | bool           | `true`  | Apply HMAC-SHA256 + Ed25519 signatures (M13). Required for `publish`. |
| `output_dir`    | string \| null | `null`  | `null` = `~/.agentguardian/scans/<scan-id>/`.                    |

### `server`

| Field   | Type   | Default     | Notes                                            |
|---------|--------|-------------|--------------------------------------------------|
| `host`  | string | `127.0.0.1` | Loopback by default. Override responsibly.       |
| `port`  | int    | `7474`      | 1–65535.                                         |

### `telemetry`

| Field      | Type | Default | Notes                                                |
|------------|------|---------|------------------------------------------------------|
| `enabled`  | bool | `false` | Opt-in only. Flip via `agent-guardian telemetry enable`. |

## CLI overrides

Every relevant config field has a corresponding CLI flag that overrides the YAML value for a single invocation:

| YAML path                       | CLI override                |
|---------------------------------|-----------------------------|
| `swarm.commander_model`         | `--commander-model`         |
| `swarm.attacker_model`          | `--attacker-model`          |
| `swarm.evaluator_model`         | `--evaluator-model`         |
| `swarm.budget.max_total_tokens` | *(no flag)*                 |
| `target.tier`                   | `--tier`                    |
| `output.formats[0]`             | `--output`                  |
| `output.output_dir`             | `--output-path`             |

`--model <spec>` is a convenience: it sets all three role models to the same spec unless a more specific role flag is also passed.

## Worked example

```yaml
# .agentguardian.yaml — CI gate config: cheap, fast, machine-readable output
swarm:
  commander_model: claude-haiku-4-5
  attacker_model:  gpt-4o-mini
  evaluator_model: gpt-4o-mini
  budget:
    wall_seconds:     300         # 5-min cap for PR checks
    max_total_tokens: 500000

output:
  formats: [sarif, junit]         # SARIF for code-scanning, JUnit for the PR
  sign_evidence: true
```

Then in CI:

```bash
agent-guardian scan --system-prompt prompt.txt --no-tui --fail-under 70
```

CLI flags (`--no-tui`, `--fail-under`) layer on top of the YAML; everything else (models, budget, output formats) comes from the file.
