# Environment variables

> **TL;DR.** The canonical list of environment variables AgentGuardian
> reads — purpose, default, and the operator scenarios where you
> actually need to set them. For dashboard auth wiring (curl examples,
> reverse-proxy headers, Kubernetes secrets), see [Serving the
> dashboard](serve.md#authentication).

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
| `AGENT_GUARDIAN_DASHBOARD_TOKEN`          | Bearer token required to access the dashboard read API. **Canonical configuration path** — `agent-guardian serve` has no `--token` CLI flag today despite an out-of-date claim in [`auth.py`'s docstring](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/auth.py#L30-L32); the docstring fix is on the [roadmap](../reference/roadmap.md). | unset (loopback-only allowed)    |
| `AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV`      | Indirection — name of *another* env var to read the dashboard token from. Useful when the token itself comes from a secret manager (Vault, AWS Secrets Manager, GCP Secret Manager) that injects into a different variable name. | unset                            |
| `AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN`   | Bearer token required to `POST /scans` (external scanners pushing events). Distinct from the read token.                                 | unset                            |
| `AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST` | Set to `1` to allow unauthenticated ingest (only for local trust boundaries — disabled by default).                                 | unset (off)                      |
| `AGENT_GUARDIAN_DASHBOARD_CORS_ORIGINS`   | Comma-separated CORS origin allowlist. Required if you serve the dashboard behind a different origin than the API.                       | unset (same-origin only)         |
| `AGENT_GUARDIAN_MAX_BUFFERED_EVENTS`      | Cap on the per-scan in-memory event deque before the oldest is evicted. Cite [`server/scan_store.py:73-102`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L73-L102). Non-positive / non-integer values fall back to the default. | `5000`                           |

## Telemetry

| Variable                                  | Purpose                                                                                                                                  | Default                                                                |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `AGENT_GUARDIAN_TELEMETRY`                | Override the saved consent tier. `off`, `essential`, or `extended`.                                                                      | from `~/.agentguardian/state.json`                                     |
| `AGENT_GUARDIAN_TELEMETRY_URL`            | Where the telemetry client POSTs events.                                                                                                 | `https://telemetry.agentguardian.ai/v1/events`                         |
| `AGENT_GUARDIAN_ANALYTICS_DB`             | Collector backend (server-side, only relevant when self-hosting `agent-guardian serve` as a telemetry collector).                        | `~/.agentguardian/analytics.db`                                        |

See [Telemetry transparency](../security/telemetry.md) for the full
data contract.

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

- [CLI exit codes](../reference/cli.md#exit-codes) — `EXIT_CONFIG` (`2`) is the
  exit code raised by env-var validation errors.
- [Configuration guide](../operations/configuration.md) — precedence chain
  (CLI flag > env var > YAML > default).
