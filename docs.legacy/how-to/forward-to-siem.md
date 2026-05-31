# Forward scan output to a SIEM

**TL;DR:** AgentGuardian emits three artefact streams a SIEM cares
about — per-event JSONL, signed JSON / SARIF reports, and a
Prometheus `/metrics` endpoint. There is **no native syslog or
webhook emitter** in v1.0; the pattern is a file-tail collector
(Fluent Bit, Vector, Filebeat) or a `/metrics` scrape, plus a
SARIF upload to the destination's code-scanning API.

## What lives where

| Stream                        | Format                          | Where it lives
| :---------------------------- | :------------------------------ | :--------------
| Per-event live stream         | NDJSON (one `SwarmEvent` per line) | `~/.agentguardian/scans/{scan_id}/events.jsonl` — **only when `agent-guardian serve` is recording**, see below
| Final signed scan record      | JSON (with HMAC + Ed25519 sig)  | `~/.agentguardian/scans/{scan_id}/scan.json` (every scan, server or CLI)
| Operator-facing reports       | SARIF / JUnit / Markdown / PDF  | Whatever `--output-path` you passed to `agent-guardian scan` or `agent-guardian report SCAN_ID --output FORMAT --output-path …`
| Server metrics                | Prometheus 0.0.4 text format    | `GET /metrics` on the running `agent-guardian serve` instance

The on-disk scan root honours `AGENT_GUARDIAN_HOME`; the default is
`~/.agentguardian` (see [Environment variables](../operations/env-vars.md)).

### When `events.jsonl` exists

`events.jsonl` is written by `ScanStore.register()`
(`src/agent_guardian/server/scan_store.py:224`) — it is the dashboard
server's on-disk replay log. **A bare CLI scan does not write it.** If
you need the per-event stream, run `agent-guardian serve` and either:

- POST the scan via the dashboard's API, or
- run scans from the same process that called
  `ScanStore.register(scan_id, swarm)` (see [`server/scan_store.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py)
  for the wiring).

The per-event deque is bounded at `MAX_BUFFERED_EVENTS_PER_SCAN`
(default `5000`, override with `AGENT_GUARDIAN_MAX_BUFFERED_EVENTS`)
so long-running scans cannot push memory unboundedly
(`scan_store.py:111`, `scan_store.py:233`).

### `events.jsonl` schema

Every line is a JSON object emitted by `event_to_payload`
(`scan_store.py:827`):

```json
{
  "kind": "agent_progress",
  "agent": "goal-hijack-agent",
  "asi": "ASI01",
  "provisional_aivss": 78,
  "decision": null,
  "timestamp": "2026-05-29T13:42:01.123456+00:00",
  "payload": {"turn": 3, "finding_count": 0}
}
```

`kind` is one of (`core/swarm.py:184–193`): `recon_start`,
`recon_done`, `agent_start`, `agent_progress`, `agent_done`,
`agent_skipped`, `checkpoint`, `scan_done`. `decision` is one of
(`core/swarm.py:379`) `continue`, `redirect`, `terminate`,
`escalate_judge`, or `null`. `asi` is the OWASP ASI category slug
(`ASI01`..`ASI10`) or `null`.

## Tail `events.jsonl` to Splunk HEC (Fluent Bit)

```ini
# fluent-bit.conf
[SERVICE]
    Flush        1
    Daemon       Off
    Log_Level    info

[INPUT]
    Name                tail
    Path                /root/.agentguardian/scans/*/events.jsonl
    Path_Key            file
    Tag                 agentguardian.events
    Parser              json
    Refresh_Interval    2
    Read_from_Head      True

[OUTPUT]
    Name              splunk
    Match             agentguardian.events
    Host              splunk.internal
    Port              8088
    TLS               On
    TLS.Verify        On
    Splunk_Token      ${SPLUNK_HEC_TOKEN}
    Splunk_Send_Raw   Off
    Event_Sourcetype  agentguardian:event
    Event_Index       security
```

The Fluent Bit `tail` input rotates safely with the LRU writer
AgentGuardian uses for the JSONL handles (`scan_store.py:111`). The
`splunk` output ships HEC-encoded JSON; `Event_Sourcetype` and
`Event_Index` give Splunk Search Processing Language a stable handle.

## Tail `events.jsonl` to Elasticsearch (Fluent Bit)

```ini
[INPUT]
    Name                tail
    Path                /root/.agentguardian/scans/*/events.jsonl
    Tag                 agentguardian.events
    Parser              json
    Read_from_Head      True

[OUTPUT]
    Name                es
    Match               agentguardian.events
    Host                elasticsearch.internal
    Port                9200
    HTTP_User           ${ES_USER}
    HTTP_Passwd         ${ES_PASSWORD}
    Index               agentguardian-events
    Logstash_Format     On
    Logstash_Prefix     agentguardian-events
    Retry_Limit         False
    Suppress_Type_Name  On
```

`Suppress_Type_Name On` is required for Elasticsearch 7.x+ since
type names are deprecated.

## Scrape `/metrics` to Grafana Cloud / Splunk Observability

`agent-guardian serve` exposes a Prometheus text-format endpoint at
`/metrics` (`server/routes/health.py:20–27`). The exposed series:

| Metric                                            | Type      | Labels
| :------------------------------------------------ | :-------- | :-----
| `agentguardian_scans_total`                       | counter   | —
| `agentguardian_scans_running`                     | gauge     | —
| `agentguardian_scan_duration_seconds`             | histogram | —
| `agentguardian_findings_total`                    | counter   | `severity`
| `agentguardian_llm_calls_total`                   | counter   | `provider`
| `agentguardian_llm_errors_total`                  | counter   | `provider`

Histogram buckets are `0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600,
1800, 3600, 14400` seconds (`health.py:66–80`). Counters are
process-local and reset on restart — single-worker deployments are
fine, multi-worker setups should aggregate at a Pushgateway or in
the load balancer.

A minimal Prometheus scrape config:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: agentguardian
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets: ['agentguardian-serve.internal:7474']
```

For Grafana Cloud remote-write, layer a Prometheus agent on top
(`remote_write` to your Grafana Cloud Prometheus endpoint).

For Splunk Observability, point the Splunk OpenTelemetry Collector's
Prometheus receiver at `/metrics`; configuration is identical to any
other Prometheus-scrape target.

## Liveness & readiness probes

Same module ships two more endpoints (`server/routes/health.py:12–19`):

- `GET /healthz` — liveness. Returns `200 {"status":"ok","version":...}`
  whenever the process is responsive. Never touches disk; safe as a
  Kubernetes `livenessProbe`.
- `GET /readyz` — readiness. Verifies the scan store's root directory
  exists and is writable; returns `200` when ready, `503
  {"status":"unavailable","reason":...}` otherwise — exactly what a
  Kubernetes `readinessProbe` expects.

## Upload SARIF to GitHub code-scanning

The signed SARIF emitter validates against the bundled SARIF 2.1.0
schema before write (`reports/sarif.py:1`, `reports/sarif.py:50`); the
schema-validation contract is enforced by
[`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py).

```bash
agent-guardian scan --system-prompt prompt.txt \
    --model openai:gpt-4o-mini \
    --no-tui \
    --output sarif \
    --output-path agentguardian.sarif
```

Then in a GitHub Actions job:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agentguardian.sarif
    category: agentguardian
```

The same SARIF file works with **Microsoft Defender for Cloud's**
SARIF upload API and **Sonatype Lifecycle**'s SARIF ingest. For the
exhaustive recipe, see [Integrate with GitHub Actions](integrate-github-actions.md).

## Re-emit reports from a stored scan

If you need to ship a different format after the fact (e.g. you
captured JSON but need SARIF for a SIEM), regenerate from the stored
scan record without re-running the swarm (cli.py:1162–1232):

```bash
agent-guardian report cli-766948e18cee \
    --output sarif \
    --output-path agentguardian.sarif
```

`cli-766948e18cee` is the `scan_id`; find recent ones with
`agent-guardian scans list`.

## What's not (yet) shipped

The following are honest gaps, tracked in [roadmap](../reference/roadmap.md):

- **Native syslog / webhook emitter.** The current SIEM integration
  story is "tail the JSONL" or "scrape `/metrics`". A direct
  webhook / RFC-5424 syslog output is a v1.x line item.
- **Per-tenant `events.jsonl` routing.** All scans live under one
  `AGENT_GUARDIAN_HOME`. Multi-tenant deployments split tenants by
  running separate `serve` processes with different homes.
- **`/metrics` aggregation across workers.** Single-worker today;
  multi-worker setups should aggregate via a Pushgateway, or run a
  sidecar that aggregates per-pod and re-exposes a combined view.

## Next steps

- For trace-level instrumentation (per-turn spans in your APM), see
  [Set up OpenTelemetry](set-up-opentelemetry.md).
- For the full env-var inventory (including the dashboard's
  bearer-token / CORS knobs), see [Environment variables](../operations/env-vars.md).
