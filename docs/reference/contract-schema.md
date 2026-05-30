# Configuration schema (`.agentguardian.yaml`)

**TL;DR.** The full YAML schema for the project-level `.agentguardian.yaml`
config file, with every field, its type, default, and source line. Every
section is optional — a `touch .agentguardian.yaml` is a valid file. CLI
flags override values here for a single invocation.

This page documents the *operator config* (`.agentguardian.yaml`).
It is separate from the *target contract* (`agentguardian.yaml` written
by `agent-guardian init`) which describes the system under test and its
Rules of Engagement; for that, run `agent-guardian contract schema --out
contract.schema.json` to dump the JSON Schema.

## Discovery order

`agent-guardian` looks for a config file in this order and uses the
first one it finds (see [`config.py:121-138`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py)):

1. The path passed via `--config PATH`.
2. `.agentguardian.yaml` in the current working directory.
3. `~/.agentguardian/config.yaml` (user-level default).

If no file is found, defaults are used. The Pydantic model uses
`extra="forbid"` at every level — typos surface immediately rather than
being silently ignored.

## Full schema with defaults

```yaml
# .agentguardian.yaml — full schema with defaults

swarm:
  commander_model: claude-haiku-4-5
  attacker_model:  gpt-4o-mini
  evaluator_model: gpt-4o-mini
  max_parallel_agents: 11
  budget:
    wall_seconds:     900
    max_total_tokens: 2000000

target:
  mode:      prompt        # prompt | code | http | framework
  path:      null
  endpoint:  null
  framework: null
  tier:      null          # null = auto-detect; or T1 | T2 | T3 | T4

output:
  formats:       [json]    # any of: json | sarif | junit | md | pdf
  redact_pii:    true
  sign_evidence: true
  output_dir:    null      # null = ~/.agentguardian/scans/<scan-id>/

server:
  host: 127.0.0.1
  port: 7474

telemetry:
  enabled: false
```

## `swarm`

Swarm-level knobs — model identifiers and budget. Defined in
[`config.py:48-56`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py).

| Field                       | Type           | Default            | Description                                                                 |
|-----------------------------|----------------|--------------------|-----------------------------------------------------------------------------|
| `commander_model`           | string         | `claude-haiku-4-5` | Role: orchestration / checkpoint decisions.                                 |
| `attacker_model`            | string         | `gpt-4o-mini`      | Role: probe generation. Cheap models work well here.                        |
| `evaluator_model`           | string         | `gpt-4o-mini`      | Role: verdict adjudication. Stronger models reduce false positives.         |
| `max_parallel_agents`       | int (1–11)     | `11`               | Cap on concurrent core ASI agents (see operational note below).             |
| `budget.wall_seconds`       | int (≥1)       | `900`              | Hard wall-clock cap. The swarm stops cleanly at this limit.                 |
| `budget.max_total_tokens`   | int (≥1)       | `2_000_000`        | Token budget. Donated across agents by the commander.                       |

Model strings here are **bare names** — no `openai:` / `anthropic:`
prefix is needed when the provider is unambiguous. See
[LLM providers overview](../integrations/providers/index.md).

**Operational note — `max_parallel_agents` vs `--no-owasp-llm`.** The
config-level cap is `1–11` (the core ASI slate maxes at 11). At scan
time, when the four OWASP-LLM specialists run by default, the CLI
raises the effective parallel cap to **14** automatically; only
`--no-owasp-llm` honours `max_parallel_agents` strictly. Source:
[`cli.py:2376`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).
See [operations / configuration](../operations/configuration.md) for the
end-to-end view.

## `target`

Target-side knobs — which mode + an optional tier override. Defined in
[`config.py:59-67`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py).

| Field        | Type                                            | Default  | Description                                                                                        |
|--------------|-------------------------------------------------|----------|----------------------------------------------------------------------------------------------------|
| `mode`       | `prompt` \| `code` \| `http` \| `framework`     | `prompt` | Adapter family.                                                                                    |
| `path`       | string \| null                                  | `null`   | Used for `code` mode.                                                                              |
| `endpoint`   | string \| null                                  | `null`   | Used for `http` mode.                                                                              |
| `framework`  | string \| null                                  | `null`   | Used for `framework` mode. One of `adk`, `autogen`, `crewai`, `langgraph`, `openai_agents`, `strands`. |
| `tier`       | `T1` \| `T2` \| `T3` \| `T4` \| null            | `null`   | `null` lets the swarm auto-detect from the fingerprint. See [target tiers](../concepts/tiers.md). |

## `output`

Output knobs — formats, redaction, signing. Defined in
[`config.py:70-77`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py).

| Field           | Type           | Default | Description                                                                              |
|-----------------|----------------|---------|------------------------------------------------------------------------------------------|
| `formats`       | list of string | `[json]`| Any combination of `json`, `sarif`, `junit`, `md`, `pdf`. See [output formats](output-formats.md). |
| `redact_pii`    | bool           | `true`  | Per-finding `summary` / `description` / `trigger_prompt` / `transcript_ref` / `evidence` are routed through `redact_finding` before emit. |
| `sign_evidence` | bool           | `true`  | Apply HMAC-SHA256 + Ed25519 signatures. Required for `publish`.                          |
| `output_dir`    | string \| null | `null`  | `null` = `~/.agentguardian/scans/<scan-id>/`.                                            |

## `server`

Dashboard (`agent-guardian serve`) defaults. Defined in
[`config.py:80-85`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py).

| Field   | Type          | Default     | Description                                            |
|---------|---------------|-------------|--------------------------------------------------------|
| `host`  | string        | `127.0.0.1` | Loopback by default. See [operations / serve](../operations/serve.md). |
| `port`  | int (1–65535) | `7474`      | Bind port.                                             |

## `telemetry`

Opt-in usage telemetry — disabled by default. Defined in
[`config.py:88-92`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py).

| Field      | Type | Default | Description                                                                          |
|------------|------|---------|--------------------------------------------------------------------------------------|
| `enabled`  | bool | `false` | Opt-in only. Flip via `agent-guardian telemetry essential` / `extended`. See [security / telemetry transparency](../security/telemetry.md). |

## CLI override map

Every relevant config field has a corresponding CLI flag that overrides
the YAML value for a single invocation. Full CLI reference:
[reference/cli.md](cli.md).

| YAML path                       | CLI override                |
|---------------------------------|-----------------------------|
| `swarm.commander_model`         | `--commander-model`         |
| `swarm.attacker_model`          | `--attacker-model`          |
| `swarm.evaluator_model`         | `--evaluator-model`         |
| `swarm.budget.wall_seconds`     | *(no flag — file/env only)* |
| `swarm.budget.max_total_tokens` | *(no flag — file/env only)* |
| `target.tier`                   | `--tier`                    |
| `output.formats[0]`             | `--output`                  |
| `output.output_dir`             | `--output-path`             |
| `server.host`                   | `--host` (on `serve`)       |
| `server.port`                   | `--port` (on `serve`)       |

`--model <spec>` is a convenience: it sets all three role models to the
same spec unless a more specific role flag is also passed.

## Worked example — CI gate config

```yaml
# .agentguardian.yaml — cheap, fast, machine-readable output for PR checks
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

CLI flags (`--no-tui`, `--fail-under`) layer on top of the YAML;
everything else (models, budget, output formats) comes from the file.
