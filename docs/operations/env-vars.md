# Environment variables

The canonical list of environment variables AgentGuardian reads, with
their purpose, default, and the operator scenarios where you actually
need to set them.

## AgentGuardian core

| Variable                                  | Purpose                                                                                                                                  | Default                          |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| `AGENT_GUARDIAN_HOME`                     | State / config / keys directory — where the first-run banner state, scan history, Ed25519 keypair, and telemetry consent live.            | `~/.agentguardian`               |
| `AGENT_GUARDIAN_LOG_LEVEL`                | Log level for the package logger (`DEBUG`, `INFO`, `WARNING`, `ERROR`).                                                                  | `INFO`                           |
| `AGENT_GUARDIAN_LOG_JSON`                 | Set to `1`/`true` to emit structured JSON logs (one record per line). Useful in CI / production.                                          | unset (text logs)                |
| `AGENT_GUARDIAN_SIGNING_SECRET`           | HMAC signing secret. Used to sign JSON reports and required by `verify --secret`. Default value is never accepted on verify.              | bundled public default           |
| `AGENT_GUARDIAN_PDF_ENGINE`               | Force the PDF engine selection — `weasyprint` or `reportlab`. Overrides auto-detection.                                                  | auto (`weasyprint` if available) |

## Provider API keys

The provider-specific API-key variables (lookup precedence: `AGENT_GUARDIAN_<PROVIDER>_API_KEY` > the provider's conventional env var):

| Variable                                  | Provider                                                          |
|-------------------------------------------|-------------------------------------------------------------------|
| `AGENT_GUARDIAN_OPENAI_API_KEY` / `OPENAI_API_KEY`       | OpenAI                                          |
| `AGENT_GUARDIAN_ANTHROPIC_API_KEY` / `ANTHROPIC_API_KEY` | Anthropic                                       |
| `AGENT_GUARDIAN_GEMINI_API_KEY` / `GEMINI_API_KEY` / `GOOGLE_API_KEY` | Google Gemini (AI Studio)            |

AWS Bedrock uses the standard AWS credential chain (`AWS_PROFILE`,
`AWS_ACCESS_KEY_ID`, etc.) — no provider-specific env var.

## Dashboard server

| Variable                                  | Purpose                                                                                                                                  | Default                          |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| `AGENT_GUARDIAN_DASHBOARD_TOKEN`          | Bearer token required to access the dashboard read API.                                                                                  | unset (loopback-only allowed)    |
| `AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV`      | Alternative — name of an env var to read the dashboard token from. Useful when the token itself comes from a secret manager.             | unset                            |
| `AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN`   | Bearer token required to POST scan events to the dashboard ingest endpoint.                                                              | unset                            |
| `AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST` | Set to `1` to allow unauthenticated ingest (only for local trust boundaries — disabled by default).                                 | unset (off)                      |
| `AGENT_GUARDIAN_DASHBOARD_CORS_ORIGINS`   | Comma-separated CORS origin allowlist. Required if you serve the dashboard behind a different origin than the API.                       | unset (same-origin only)         |
| `AGENT_GUARDIAN_MAX_BUFFERED_EVENTS`      | Cap on the number of events the dashboard buffers in memory before dropping oldest. Bound the ScanStore deque (default 5000).            | `5000`                           |

## Telemetry

| Variable                                  | Purpose                                                                                                                                  | Default                                                                |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `AGENT_GUARDIAN_TELEMETRY`                | Override the saved consent tier. `off`, `essential`, or `extended`.                                                                      | from `~/.agentguardian/state.json`                                     |
| `AGENT_GUARDIAN_TELEMETRY_URL`            | Where the telemetry client POSTs events.                                                                                                 | `https://telemetry.agentguardian.ai/v1/events`                         |
| `AGENT_GUARDIAN_ANALYTICS_DB`             | Collector backend (server-side, only relevant when self-hosting `agent-guardian serve` as a telemetry collector).                        | `~/.agentguardian/analytics.db`                                        |

See [Telemetry transparency](../telemetry/index.md) for the full data
contract.

## Observability (OpenTelemetry)

| Variable                              | Purpose                                                                                                  |
|---------------------------------------|----------------------------------------------------------------------------------------------------------|
| `OTEL_SEMCONV_STABILITY_OPT_IN`       | Must contain `gen_ai_latest_experimental` to enable GenAI spans. Otherwise observability is a no-op.     |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`  | OTLP traces endpoint (takes precedence over the generic endpoint).                                       |
| `OTEL_EXPORTER_OTLP_ENDPOINT`         | Generic OTLP endpoint.                                                                                   |
| `OTEL_EXPORTER_OTLP_HEADERS`          | Comma-separated `k=v` list — used to authenticate to hosted collectors.                                  |
| `OTEL_SERVICE_NAME`                   | Override `service.name` resource attribute. Defaults to `agent-guardian`.                                |

See [Observability](observability.md) for span catalog and worked
examples.

## Where else env vars are referenced

- [CLI exit codes](../cli.md#exit-codes) — `EXIT_CONFIG` (`2`) is the
  exit code raised by env-var validation errors.
- [Configuration guide](../guide/configuration.md) — precedence chain
  (CLI flag > env var > YAML > default).
