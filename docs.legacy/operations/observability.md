# Observability

> **TL;DR.** AgentGuardian emits OpenTelemetry GenAI spans (gated behind
> an opt-in env var) plus structured JSON logs (one record per line). This
> page is the span catalog and the log schema — what we set, where we set
> it, and what we honestly do *not* yet emit.

## Quick start

Two conditions must hold before AgentGuardian produces a real tracer.
The gate is at
[`obs/otel.py:148-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L148-L158):

1. `OTEL_SEMCONV_STABILITY_OPT_IN` contains the literal token
   `gen_ai_latest_experimental`.
2. `opentelemetry` is importable in the runtime.

If either is missing, every observability call is a silent no-op.
Nothing is imported eagerly, nothing raises. The opt-in token is
required because the OpenTelemetry GenAI conventions are still
experimental — we follow the SDK's own gating convention rather than
emit attributes that may churn.

```bash
export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
export OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io
export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=$HONEYCOMB_API_KEY"
export OTEL_SERVICE_NAME=agent-guardian
agent-guardian scan --system-prompt prompt.txt
```

For backend-specific recipes (Honeycomb, Grafana Tempo, Jaeger, the
OpenTelemetry Collector), see the OpenTelemetry SDK exporter
documentation. The variables above are the standard
`OTEL_EXPORTER_OTLP_*` set — anything that consumes them works.

## Span families

AgentGuardian instruments three span families. Their lifetimes nest:
`invoke_agent` wraps a specialist agent's full turn-cycle; each turn
opens one `transport.send` (the per-turn HTTP call to the target);
each tool the target invokes inside that turn opens one
`execute_tool`.

| Span name                          | Span kind | Source                                                                                                |
|------------------------------------|-----------|-------------------------------------------------------------------------------------------------------|
| `invoke_agent {agent_name}`        | `CLIENT`  | [`obs/otel.py:195-210`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L195-L210) |
| `transport.send {endpoint}`        | `CLIENT`  | [`obs/otel.py:233-251`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L233-L251) |
| `execute_tool {tool_name}`         | (default) | [`obs/otel.py:254-265`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L254-L265) |

## Attribute catalog

The list below is what AgentGuardian's code *actually* sets. Every row
cites the line at which the attribute is written. If you do not see a
row, the attribute is not emitted — see [What we do not yet
emit](#what-we-do-not-yet-emit).

| Span                  | Attribute / event                   | Type           | Source                                                                                                              |
|-----------------------|-------------------------------------|----------------|---------------------------------------------------------------------------------------------------------------------|
| `invoke_agent`        | `gen_ai.operation.name`             | string         | [`obs/otel.py:206`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L206) (`agent_span`), [`obs/otel.py:326`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L326) (observer) |
| `invoke_agent`        | `gen_ai.agent.name`                 | string         | [`obs/otel.py:207`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L207), [`obs/otel.py:327`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L327)         |
| `invoke_agent`        | `gen_ai.conversation.id`            | string         | [`obs/otel.py:209`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L209) (when supplied) |
| `invoke_agent`        | `gen_ai.usage.input_tokens`         | int            | [`obs/otel.py:284`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L284) (`set_usage`)   |
| `invoke_agent`        | `gen_ai.usage.output_tokens`        | int            | [`obs/otel.py:286`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L286)               |
| `invoke_agent`        | span event `gen_ai.provisional_aivss` (carries `agent_guardian.provisional_aivss` int) | event | [`obs/otel.py:336-338`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L336-L338) |
| `transport.send`      | `server.address`                    | string (host)  | [`obs/otel.py:248`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L248) — bare host, per OTel semconv (not the full URL) |
| `transport.send`      | `server.port`                       | int            | [`obs/otel.py:250`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L250) — derived from the scheme when implicit |
| `execute_tool`        | `gen_ai.operation.name`             | string         | [`obs/otel.py:262`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L262)               |
| `execute_tool`        | `gen_ai.tool.name`                  | string         | [`obs/otel.py:263`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L263)               |
| `execute_tool`        | `gen_ai.tool.type`                  | string         | [`obs/otel.py:264`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L264) — `function` is the default; adapters can override (`mcp`, etc.) |

### What we do not yet emit

The OTel GenAI conventions catalogue a longer list of `gen_ai.*`
attributes. The ones AgentGuardian does **not** set today:

- `gen_ai.system` (provider id — `openai`, `anthropic`, …)
- `gen_ai.request.model`, `gen_ai.response.model`
- `gen_ai.request.max_tokens`, `gen_ai.request.temperature`
- `gen_ai.response.finish_reasons`
- `http.request.method`, `http.response.status_code` on
  `transport.send` (previous versions of this doc claimed these — they
  were not actually emitted; the doc has been corrected)

These are tracked as future work; see [roadmap.md](../reference/roadmap.md).
Adding them is a single-PR, well-scoped change for any contributor.

## Consuming spans the target emits

`configure_otel`
([`obs/otel.py:455-502`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/obs/otel.py#L455-L502))
wires AgentGuardian's *own* spans through an OTLP-HTTP exporter. A
separate seam — `obs/otel_consumer.py` —
ingests spans the *target* itself emits, when its contract declares
`observability.otel_endpoint`
([`contract/schema.py:699-705`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/contract/schema.py#L699-L705)).
That lets the dashboard correlate AgentGuardian's `invoke_agent` /
`transport.send` spans with the target-side `chat-completion`,
`tool-call`, etc. spans, on the same `trace_id`.

Practically: if your target also exports OpenTelemetry to the same
OTLP collector, both span families will show up under one
parent-of-parents trace. The provisional AIVSS event lands on the
`invoke_agent` span that triggered the target call, which makes
"why did this score fall?" answerable from the trace view alone.

## Structured logging

Set `AGENT_GUARDIAN_LOG_JSON=1` to emit one JSON object per log line.
Wired at
[`logging_setup.py:50`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/logging_setup.py#L50)
(env var) and
[`logging_setup.py:170-261`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/logging_setup.py#L170-L261)
(the structlog JSON pipeline).

```bash
export AGENT_GUARDIAN_LOG_JSON=1
export AGENT_GUARDIAN_LOG_LEVEL=INFO
agent-guardian scan --system-prompt prompt.txt --model stub
```

### Field schema

Every record carries (when populated):

| Field         | Type                  | Notes                                                                                  |
|---------------|-----------------------|----------------------------------------------------------------------------------------|
| `event`       | string                | The log message.                                                                       |
| `level`       | string                | `debug` / `info` / `warning` / `error` — lowercase.                                    |
| `timestamp`   | ISO-8601 UTC string   | E.g. `2026-05-30T12:34:56.789012Z`.                                                    |
| `logger`      | string                | The Python logger name (e.g. `agent_guardian.core.swarm`).                             |
| `trace_id`    | string (32 hex chars) | W3C trace-context — set when an OTel span is active. Absent otherwise.                 |
| `span_id`     | string (16 hex chars) | W3C trace-context — set when an OTel span is active.                                   |
| `trace_flags` | string (2 hex chars)  | W3C trace-context — set when an OTel span is active.                                   |

The trace-correlation fields are stamped by the LogRecord factory at
[`logging_setup.py:110-167`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/logging_setup.py#L110-L167).
When no OTel span is active they are simply omitted from the JSON
object.

`structlog` is a hard runtime dependency
([`pyproject.toml:72`](https://github.com/glacien-technologies/agent-guardian/blob/main/pyproject.toml#L72)) — the
JSON pipeline does not silently fall back to a fragile alternative
when it is missing.

### Library logs flow through the same pipeline

httpx, the OTel SDK, urllib3, and Google's GenAI SDK all use the
stdlib `logging` module. AgentGuardian installs a `ProcessorFormatter`
on the root handler
([`logging_setup.py:249-260`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/logging_setup.py#L249-L260))
so every stdlib record is rendered through the *same* structlog
processor chain — same JSON shape, same redaction, same trace
correlation. There is no separate library-log channel to ship.

### Secrets redaction

Three regex families scrub secrets before any record is written —
[`logging_setup.py:65-101`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/logging_setup.py#L65-L101):

1. Sensitive query params: `?key=`, `?api_key=`, `?access_token=`,
   `?token=`, `?sig=`, `?signature=`.
2. `Authorization: Bearer <token>` headers.
3. Bare provider key shapes: Google `AIza…`, OpenAI / Anthropic `sk-…`.

Defence-in-depth — applied as a `logging.Filter` on the root handler
so even chatty deps like httpx (which logs request URLs containing
`?key=…`) are scrubbed.

### Sample line

```json
{
  "event": "scan started",
  "level": "info",
  "timestamp": "2026-05-30T12:34:56.789012Z",
  "logger": "agent_guardian.cli",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "trace_flags": "01"
}
```

### Fluent Bit parser

```ini
[PARSER]
    Name        ag-json
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S.%LZ
    Time_Keep   On
```

### Vector parser

```toml
[transforms.ag_parse]
type = "remap"
inputs = ["docker"]
source = '''
. = parse_json!(string!(.message))
.timestamp = parse_timestamp!(.timestamp, "%Y-%m-%dT%H:%M:%S%.fZ")
'''
```

### Docker / journald hygiene

The Docker JSON-file driver has no upper bound by default — a long
scan can fill the disk. Pin a rotation policy in your daemon config:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "10"
  }
}
```

On systemd hosts, journald rotates by default; the relevant knobs are
`SystemMaxUse=` and `SystemMaxFiles=` in `/etc/systemd/journald.conf`.

## See also

- [Performance](performance.md) — single-worker assumption that
  applies to `/metrics`; in-memory event buffer overflow logs that
  surface here.
- [Environment variables](env-vars.md#observability-opentelemetry) —
  the full env-var catalog (OTLP endpoint, headers, service name).
- [Operator runbook](runbook.md) — what a typical structured log line
  looks like for each documented failure mode.
- [CLI reference — `--otel-endpoint`](../reference/cli.md#options) — the `scan`
  subcommand flag for the OTLP traces endpoint.
