# Configuration

> **TL;DR.** The full `.agentguardian.yaml` schema with every default,
> every type, and source-citations to the Pydantic models. CLI flag
> overrides and the precedence chain are documented at the bottom.

AgentGuardian reads settings from four sources, in descending
precedence:

1. **Explicit CLI flags** — `--model`, `--tier`, `--budget-usd`, ...
2. **Environment variables** — `AGENT_GUARDIAN_*` and conventional ones
   like `OPENAI_API_KEY`.
3. **YAML config file** — discovered automatically (see below).
4. **Defaults** — baked into the `Config` Pydantic model at
   [`config.py:95-108`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L95-L108).

The model uses `extra="forbid"` at every level — typos in your YAML
surface as a validation error rather than being silently ignored. See
[`config.py:40-108`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L40-L108) for the canonical types.

## Config-file discovery

`agent-guardian` looks for a config file in this order and uses the
first match (see [`config.py:121-138`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L121-L138)):

1. The path passed via `--config PATH`.
2. `.agentguardian.yaml` in the current working directory.
3. `~/.agentguardian/config.yaml` (user-level default).

If no file is found, the defaults below are used. You can start with
an empty file (`touch .agentguardian.yaml`) and grow into the schema —
every section is optional and falls back to its default sub-model.

## Full schema

```yaml
# .agentguardian.yaml — full schema with defaults

swarm:
  commander_model: claude-haiku-4-5     # commander LLM role
  attacker_model:  gpt-4o-mini          # attacker LLM role
  evaluator_model: gpt-4o-mini          # evaluator LLM role
  max_parallel_agents: 11               # 1–11 (see note below — overridden by --owasp-llm)
  budget:
    wall_seconds:     900               # 15 min hard cap
    max_total_tokens: 2000000

target:
  mode:      prompt                     # one of: prompt | code | http | framework
  path:      null                       # for code mode (MODULE:ATTR)
  endpoint:  null                       # for http mode (URL)
  framework: null                       # for framework mode (langgraph | crewai | autogen | openai_agents | strands | adk)
  tier:      null                       # null = auto-detect; or T1 | T2 | T3 | T4

output:
  formats:       [json]                 # any combination of: json | sarif | junit | md | pdf
  redact_pii:    true                   # strip PII from transcripts before emit
  sign_evidence: true                   # HMAC-SHA256 + Ed25519 signatures
  output_dir:    null                   # null = ~/.agentguardian/scans/<scan-id>/

server:
  host: 127.0.0.1                       # dashboard bind host
  port: 7474                            # dashboard bind port (1–65535)

telemetry:
  enabled: false                        # opt-in only — see Telemetry transparency
```

## Section reference

### `swarm`

Source: [`config.py:48-56`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L48-L56).

| Field                       | Type            | Default            | Notes                                                                 |
|-----------------------------|-----------------|--------------------|-----------------------------------------------------------------------|
| `commander_model`           | string          | `claude-haiku-4-5` | Role: orchestration / checkpoint decisions.                           |
| `attacker_model`            | string          | `gpt-4o-mini`      | Role: probe generation. Cheap models work well here.                  |
| `evaluator_model`           | string          | `gpt-4o-mini`      | Role: verdict adjudication. Stronger models reduce false positives.   |
| `max_parallel_agents`       | int (1–11)      | `11`               | Cap on concurrent ASI agents. Lower for rate-limited tiers.           |
| `budget.wall_seconds`       | int (≥1)        | `900`              | Hard wall-clock cap. The swarm stops cleanly at this limit.           |
| `budget.max_total_tokens`   | int (≥1)        | `2_000_000`        | Token budget. Donated across agents by the commander.                 |

Model strings here are **bare names** — no `openai:` / `anthropic:`
prefix. The provider is inferred from the prefix (or specified
explicitly when needed). See
[LLM Providers](../integrations/providers/index.md) for the resolution rules.

!!! warning "`max_parallel_agents` is overridden by `--owasp-llm`"
    The bound `1 ≤ max_parallel_agents ≤ 11` on the Pydantic field is
    correct *today* for the base ASI slate, but the `scan` CLI
    overrides it when the OWASP-LLM specialist agents are active. Per
    [`cli.py:2376`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2376):

    ```python
    max_parallel_agents=(
        min(10, cfg.swarm.max_parallel_agents) if no_owasp_llm else 14
    )
    ```

    In practice this means:

    - default scan (OWASP-LLM **on**): parallel cap is hard-coded to
      `14`, regardless of what your YAML says.
    - `--no-owasp-llm`: parallel cap is `min(10, your_value)`.

    Your YAML `max_parallel_agents` only takes effect on the
    `--no-owasp-llm` branch. The v1.1 fix that makes `config.py`
    respect both branches and reconciles the upper bound (11 vs 14) is
    tracked in [roadmap.md](../reference/roadmap.md).

### `target`

Source: [`config.py:59-67`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L59-L67).

| Field        | Type                                         | Notes                                              |
|--------------|----------------------------------------------|----------------------------------------------------|
| `mode`       | `prompt` \| `code` \| `http` \| `framework`  | Default `prompt`.                                  |
| `path`       | string \| null                               | Only used for `code` mode. `MODULE:ATTR` form.     |
| `endpoint`   | string \| null                               | Only used for `http` mode. Full URL.               |
| `framework`  | string \| null                               | One of `langgraph` / `crewai` / `autogen` / `openai_agents` / `strands` / `adk`. Native object is supplied via `--framework-ref MODULE:ATTR`. |
| `tier`       | `T1`–`T4` \| null                            | `null` lets the swarm auto-detect from fingerprint. |

The `framework` adapter classes ship today; the CLI dispatch is wired
in `scan`. See
[`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L104-L111) for the
adapter registry and
[Targets & Adapters — Framework](../integrations/adapters/framework.md) for the
recipe.

### `output`

Source: [`config.py:70-77`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L70-L77).

| Field           | Type            | Default | Notes                                                            |
|-----------------|-----------------|---------|------------------------------------------------------------------|
| `formats`       | list of string  | `[json]`| Any combination of `json`, `sarif`, `junit`, `md`, `pdf`.        |
| `redact_pii`    | bool            | `true`  | Per-finding `summary` runs through `PiiRedactor` before emit.    |
| `sign_evidence` | bool            | `true`  | Apply HMAC-SHA256 + Ed25519 signatures. Required for `publish`. |
| `output_dir`    | string \| null  | `null`  | `null` = `~/.agentguardian/scans/<scan-id>/`.                    |

### `server`

Source: [`config.py:80-85`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L80-L85).

| Field   | Type   | Default     | Notes                                            |
|---------|--------|-------------|--------------------------------------------------|
| `host`  | string | `127.0.0.1` | Loopback by default. Override responsibly — see [Serving the dashboard](serve.md#bind-and-a-loud-bind-warning). |
| `port`  | int    | `7474`      | 1–65535. The default collides with Neo4j's browser port; that is intentional — see [FAQ](../faq/index.md). |

### `telemetry`

Source: [`config.py:88-92`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L88-L92).

| Field      | Type | Default | Notes                                                |
|------------|------|---------|------------------------------------------------------|
| `enabled`  | bool | `false` | Opt-in only. Flip via `agent-guardian telemetry enable`. |

## CLI overrides

Every YAML field listed has a corresponding CLI flag that overrides
its value for a single invocation:

| YAML path                       | CLI override                |
|---------------------------------|-----------------------------|
| `swarm.commander_model`         | `--commander-model`         |
| `swarm.attacker_model`          | `--attacker-model`          |
| `swarm.evaluator_model`         | `--evaluator-model`         |
| `swarm.budget.max_total_tokens` | *(no flag — YAML only)*     |
| `target.tier`                   | `--tier`                    |
| `target.mode`                   | `--system-prompt` / dotted path / `--endpoint` / `--framework` / `--contract` |
| `output.formats[0]`             | `--output`                  |
| `output.output_dir`             | `--output-path`             |

`--model <spec>` is a convenience: it sets all three role models to
the same spec unless a more specific role flag is also passed.

For environment-variable resolution rules see
[Environment variables](env-vars.md); the CLI-to-env-to-YAML precedence
is enforced in [`config.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py)
and the CLI layer applies flag overrides on top.

## Worked example — CI gate

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

CLI flags (`--no-tui`, `--fail-under`) layer on top of the YAML;
everything else (models, budget, output formats) comes from the file.

## See also

- [Environment variables](env-vars.md) — the env-var layer the CLI
  consults before falling back to YAML.
- [Serving the dashboard](serve.md) — the `server.host` / `server.port`
  fields in context.
- [Performance — tuning levers](performance.md#tuning-levers) — which
  fields actually move scan wall-time.
- [Scan modes](../concepts/scan-modes.md) — what `--mode` does to the
  effective config.
