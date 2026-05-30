# Set up OpenTelemetry

**TL;DR:** opt in to the experimental GenAI semantic conventions, set
an OTLP-HTTP endpoint, and AgentGuardian emits `invoke_agent`,
`transport.send`, and `execute_tool` spans with `gen_ai.*` attributes
for every scan. Without the opt-in token, observability is a silent
no-op — zero performance cost.

For background on what's instrumented (span catalog + attributes), see
[Observability](../operations/observability.md).

## The opt-in gate (read this first)

Two conditions must hold before AgentGuardian produces a real tracer;
otherwise every observability call is a silent no-op
(obs/otel.py:85–86, obs/otel.py:148–157):

1. The `opentelemetry` SDK is importable in the environment.
2. The environment variable `OTEL_SEMCONV_STABILITY_OPT_IN` contains
   the token `gen_ai_latest_experimental`.

The opt-in is required because the OpenTelemetry GenAI conventions are
still experimental — we follow the SDK's own gating convention rather
than silently emit attributes that may churn.

```bash
export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
```

If you skip this, the rest of this page is a no-op and the scan will
behave as if OTel were not installed.

## Pick a backend

=== "Honeycomb"

    Honeycomb's OTLP/HTTP traces endpoint is
    `https://api.honeycomb.io/v1/traces` (the SDK appends `v1/traces`
    automatically when you set the base endpoint to
    `https://api.honeycomb.io`). Authentication is via the
    `x-honeycomb-team` header.

    ```bash
    export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
    export OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io
    export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=$HONEYCOMB_API_KEY"
    export OTEL_SERVICE_NAME=agent-guardian

    agent-guardian scan --system-prompt prompt.txt \
        --model openai:gpt-4o-mini \
        --no-tui
    ```

=== "Grafana Cloud"

    Grafana Cloud's OTLP-HTTP endpoint and credentials are
    stack-specific — copy them from your stack's **OpenTelemetry**
    config card in the Grafana Cloud console. The pattern is
    `https://otlp-gateway-<zone>.grafana.net/otlp` with a `Basic` auth
    header whose value is the base64-encoding of
    `<instance-id>:<token>`.

    ```bash
    export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
    export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-us-central-0.grafana.net/otlp
    export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $(printf '%s:%s' "$GRAFANA_INSTANCE_ID" "$GRAFANA_CLOUD_TOKEN" | base64)"
    export OTEL_SERVICE_NAME=agent-guardian

    agent-guardian scan --system-prompt prompt.txt \
        --model openai:gpt-4o-mini \
        --no-tui
    ```

    The `Authorization=` value as configured here is the literal
    Basic-auth header AgentGuardian sends — confirm the exact URL and
    base64 payload against the values your Grafana Cloud console
    displays.

=== "Datadog"

    Datadog's OTLP-HTTP **logs** and **metrics** intakes are GA; the
    OTLP-HTTP **traces** intake is in preview at the time of writing
    and requires access from your Customer Success Manager. The
    documented direct-ingest configuration uses the `dd-api-key`
    header and the OTLP/HTTP Protobuf encoding (set
    `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` — AgentGuardian uses
    the `opentelemetry-exporter-otlp-proto-http` exporter, which
    matches this).

    ```bash
    export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
    export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
    export OTEL_EXPORTER_OTLP_ENDPOINT=https://trace.agent.datadoghq.com
    export OTEL_EXPORTER_OTLP_HEADERS="dd-api-key=$DD_API_KEY"
    export OTEL_SERVICE_NAME=agent-guardian

    agent-guardian scan --system-prompt prompt.txt \
        --model openai:gpt-4o-mini \
        --no-tui
    ```

    Datadog uses regional intakes (`datadoghq.com`, `datadoghq.eu`,
    `us3.datadoghq.com`, …); use the one your account lives on.

=== "Self-hosted (Tempo / Jaeger)"

    A self-hosted OpenTelemetry collector, Grafana Tempo, or Jaeger
    instance running OTLP-HTTP on the standard port `4318`. No auth
    headers required by default.

    ```bash
    export OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental
    export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
    export OTEL_SERVICE_NAME=agent-guardian

    agent-guardian scan --system-prompt prompt.txt \
        --model openai:gpt-4o-mini \
        --no-tui
    ```

    The CLI accepts `--otel-endpoint` as an explicit alternative to
    the env var (cli.py:2156–2168) — useful in CI pipelines where
    you don't want to leak the endpoint into the job-level environment:

    ```bash
    agent-guardian scan --system-prompt prompt.txt \
        --model openai:gpt-4o-mini \
        --otel-endpoint http://localhost:4318 \
        --no-tui
    ```

## Endpoint precedence

The resolved endpoint follows the OTel-spec precedence chain
(obs/otel.py:418–438):

1. `--otel-endpoint` (or the `endpoint` argument to
   `configure_otel`).
2. `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (trace-specific).
3. `OTEL_EXPORTER_OTLP_ENDPOINT` (generic OTLP endpoint).

When none of the three are set, `configure_otel` returns `None` and
no exporter is wired (obs/otel.py:480–482). This is the default — a
fresh install pays nothing for OpenTelemetry.

## What gets emitted

Three span families, all tagged with `gen_ai.*` attributes from the
OpenTelemetry GenAI semantic conventions
(obs/otel.py:74–80):

| Span                              | Span kind  | Key attributes
| :-------------------------------- | :--------- | :--------------
| `invoke_agent {agent_name}`       | `CLIENT`   | `gen_ai.operation.name=invoke_agent`, `gen_ai.agent.name`, `gen_ai.conversation.id`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`
| `transport.send {endpoint}`       | `CLIENT`   | `server.address` (bare host), `server.port`, `http.request.method`, `http.response.status_code`
| `execute_tool {tool_name}`        | `CLIENT`   | `gen_ai.operation.name=execute_tool`, `gen_ai.tool.name`, `gen_ai.tool.type`

`server.address` is the bare host, not the full URL — per the OTel
semantic convention. This was a deliberate change in commit
`a8c8ee6` (launch readiness fixes).

## Verifying it actually works

1. **Confirm the gate is on.** With the env var unset, AgentGuardian
   never imports `opentelemetry` at runtime — verify by running with
   `AGENT_GUARDIAN_LOG_LEVEL=DEBUG` and grepping for `otel` log lines.
2. **Hit a local collector first.** Spin up a Jaeger
   all-in-one container (`docker run --rm -p 4318:4318 -p 16686:16686
   jaegertracing/all-in-one:latest`), point AgentGuardian at it, run
   a stub scan, and confirm the spans appear in the Jaeger UI at
   `http://localhost:16686`.
3. **Then point at production.** Vendor endpoints are stricter about
   payload format; if a span shows up locally but not in your APM,
   the diagnosis is almost always an auth header typo or a regional
   intake mismatch.

## What's not (yet) wired

`configure_otel` exports only the spans **AgentGuardian itself**
produces. Consuming spans the *target* emits — so AgentGuardian can
correlate its adversarial probes with the target's existing tracing —
is left as a documented stub (obs/otel.py:472–476). Track [roadmap](../reference/roadmap.md)
"Stage 3" for the consumer exporter.

## Next steps

- For sending the full scan report stream to a SIEM (not just spans),
  see [Forward to a SIEM](forward-to-siem.md).
- For the full env-var inventory, see [Environment variables](../operations/env-vars.md).
