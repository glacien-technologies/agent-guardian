# Observability

AgentGuardian emits OpenTelemetry GenAI spans so an operator can
correlate the adversarial swarm with their existing observability
backend (Honeycomb, Grafana Tempo, an OTLP-compatible Jaeger, etc.).

## Gate

OTel is **gated and degrades to a no-op**. Two conditions must hold
before AgentGuardian produces a real tracer; otherwise every
observability call is a silent no-op:

1. The `opentelemetry` SDK is importable in the environment.
2. The environment variable `OTEL_SEMCONV_STABILITY_OPT_IN` contains
   the token `gen_ai_latest_experimental`.

The opt-in token is required because the OpenTelemetry GenAI
conventions are still experimental — we follow the SDK's own gating
convention rather than silently emit attributes that may churn.

## Configuration

| Variable                              | Purpose                                                                                                  |
|---------------------------------------|----------------------------------------------------------------------------------------------------------|
| `OTEL_SEMCONV_STABILITY_OPT_IN`       | Must contain `gen_ai_latest_experimental` to enable GenAI spans. Otherwise observability is a no-op.     |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`  | OTLP traces endpoint. Takes precedence over the generic endpoint when both are set.                      |
| `OTEL_EXPORTER_OTLP_ENDPOINT`         | Generic OTLP endpoint (traces + metrics + logs share it unless trace-specific override is set).          |
| `OTEL_EXPORTER_OTLP_HEADERS`          | Comma-separated `k=v` list — used to authenticate to hosted collectors (Honeycomb, Grafana, etc.).       |
| `OTEL_SERVICE_NAME`                   | Override `service.name` resource attribute. Defaults to `agent-guardian`.                                |

Example — push to a hosted Honeycomb endpoint:

```bash
export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
export OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io
export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=$HONEYCOMB_API_KEY"
export OTEL_SERVICE_NAME=agent-guardian
agent-guardian scan --system-prompt prompt.txt
```

## Span catalog

AgentGuardian instruments three span families. All carry the standard
`gen_ai.*` attributes from the OpenTelemetry GenAI semantic
conventions.

### `invoke_agent {agent_name}`

Spans one specialist agent's full lifetime within a scan. Span kind
`CLIENT`. Attributes:

- `gen_ai.operation.name` = `invoke_agent`
- `gen_ai.agent.name`     = the specialist's slug (`goal-hijack-agent`,
                            `tool-abuse-agent`, …)
- `gen_ai.conversation.id` (when supplied)
- `gen_ai.usage.input_tokens` / `gen_ai.usage.output_tokens` set on
  completion.

### `transport.send {endpoint}`

Spans one per-turn HTTP send to the target endpoint. Span kind
`CLIENT`. Attributes:

- `server.address` — bare host (not the full URL), per the OTel
  semantic convention.
- `server.port`    — numeric port when known (derived from the URL
  scheme when implicit).
- `http.request.method`, `http.response.status_code` when available.

### `execute_tool {tool_name}`

Spans one tool invocation observed via the contract adapter. Span kind
`CLIENT`. Attributes:

- `gen_ai.operation.name` = `execute_tool`
- `gen_ai.tool.name`      = the tool's declared name.
- `gen_ai.tool.type`      = tool category (`mcp`, `function`, …) where
  the adapter exposes one.

## What if I have not opted in to the experimental conventions?

Everything still works — `agent-guardian` emits no spans and never
touches the OTel SDK. There is no performance penalty and no log
noise; the gate is checked once at import.

## Stage 3 — consuming spans the target emits

`configure_otel` leaves a documented stub for the exporter that
*consumes* spans the target itself emits (so AgentGuardian can correlate
its adversarial probes with the target's existing tracing). The
consumer transport lands in a future release; the gate above remains
the same.
