# Serving the dashboard

> **TL;DR.** How to bind, authenticate, scrape, and front the AgentGuardian
> dashboard in production. Covers `serve` bind options, Bearer auth, the three
> Kubernetes-ready endpoints (`/healthz`, `/readyz`, `/metrics`), and reverse-proxy
> snippets for Caddy and nginx.

The dashboard is a single-process FastAPI app the CLI starts with
`agent-guardian serve`. It is designed to be sat behind a reverse proxy
(TLS, request logging, rate limiting) — the in-process surface ships
loopback-only by default and gains Bearer auth as soon as you set a token.

## Bind, and a loud bind-warning

The `serve` subcommand exposes three flags — `--host`, `--port`, and
`--reload`. Defaults are `127.0.0.1:7474`; see
[CLI reference — `serve`](../reference/cli.md#serve) for the canonical Typer
declaration.

```bash
# Loopback only — safe default.
agent-guardian serve
# Listening at http://127.0.0.1:7474

# Bind to all interfaces (off-loopback). Prints a WARNING to stderr.
agent-guardian serve --host 0.0.0.0 --port 7474
```

Binding to a non-loopback host (anything other than `127.0.0.1`,
`localhost`, or `::1`) emits the warning hard-coded at
[`src/agent_guardian/cli.py:1129-1140`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L1129-L1140):

```text
WARNING: binding the dashboard to a non-loopback host (0.0.0.0). This
exposes scan history (target URLs + findings) and the telemetry-ingest
endpoint to the network. The dashboard ships NO authentication for its
read views -- only run this on a trusted network, behind your own auth
proxy. ...
```

That warning is the truthful default. The next section is how to fix it.

## Authentication

Dashboard authentication is opt-in. When a token is configured the auth
dependency at
[`src/agent_guardian/server/auth.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/auth.py)
fails closed on every protected route.

### Configure the read token (`AGENT_GUARDIAN_DASHBOARD_TOKEN`)

Set the env var **before** starting the server. There is no `--token`
CLI flag today — the `auth.py` module docstring mentions one, but
`agent-guardian serve --help` only ships `--host`, `--port`, `--reload`.
See the [roadmap note](#known-divergence-serve-has-no-token-flag) below.

```bash
export AGENT_GUARDIAN_DASHBOARD_TOKEN=$(openssl rand -hex 32)
agent-guardian serve --host 0.0.0.0 --port 7474
```

Once set, every request to the protected routes (`/scans`, `/scans/{id}`,
the SPA shell, report mutations) must satisfy **one** of:

1. originate from a loopback client (the allow-list is verbatim
   [`src/agent_guardian/server/auth.py:70`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/auth.py#L70):
   `127.0.0.1`, `::1`, `localhost`, `testclient`), **or**
2. carry an `Authorization: Bearer <token>` header (constant-time
   compared with `secrets.compare_digest`), **or**
3. carry the HMAC-signed `ag_dash` cookie minted from a `?token=...`
   query exchange.

Anything else gets `401 Unauthorized` with
`WWW-Authenticate: Bearer realm="dashboard"`.

```bash
# Curl with Bearer
curl -sS \
  -H "Authorization: Bearer $AGENT_GUARDIAN_DASHBOARD_TOKEN" \
  http://dashboard.internal:7474/scans
```

### Token-from-secret-manager (`AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV`)

Operators who pull secrets from a manager (Vault, AWS Secrets Manager,
GCP Secret Manager) often have their secrets-injection sidecar
land the secret in a *different* env var. `AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV`
is a level of indirection — name the env var that *holds* the token.
The auth layer reads it lazily so a rotated secret takes effect on the
next request.

```bash
export VAULT_DASHBOARD_TOKEN=...   # injected by your secrets sidecar
export AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV=VAULT_DASHBOARD_TOKEN
agent-guardian serve --host 0.0.0.0 --port 7474
```

### Ingest token (`AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN`)

Distinct from the read token. Guards `POST /scans` so external scanners
can push events without granting them read access to the full scan
history. Set both vars when you serve off-loopback.

```bash
export AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN=$(openssl rand -hex 32)
```

### Public-ingest escape hatch (`AGENT_GUARDIAN_DASHBOARD_ALLOW_PUBLIC_INGEST`)

Set to `1` to allow unauthenticated `POST /scans`. Only use this on
trust boundaries you already control (e.g. a private VPC where the
network layer is the authentication layer). Disabled by default.

### CORS allow-list (`AGENT_GUARDIAN_DASHBOARD_CORS_ORIGINS`)

Comma-separated allow-list. Required only when the dashboard SPA is
served from a different origin than the API (e.g. a separate marketing
domain proxies the dashboard). Unset = same-origin only.

### Known divergence: `serve` has no `--token` flag

The
[`auth.py` docstring](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/auth.py#L30-L32)
claims `serve --token` exists. It does not — `agent-guardian serve
--help` lists only `--host`, `--port`, `--reload` (see
[CLI reference — `serve`](../reference/cli.md#serve)). The env-var path
(`AGENT_GUARDIAN_DASHBOARD_TOKEN` / `AGENT_GUARDIAN_DASHBOARD_TOKEN_ENV`)
is the only path today. Tracking the docstring fix in
[roadmap.md](../reference/roadmap.md).

## `/healthz` — liveness

```http
GET /healthz HTTP/1.1
```

Returns `200 {"status":"ok","version":"1.0.0"}`. Never touches disk.
Cheap. Cite
[`server/routes/health.py:243-246`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L243-L246).

```bash
curl -sS http://127.0.0.1:7474/healthz
# {"status":"ok","version":"1.0.0"}
```

Kubernetes `livenessProbe`:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 7474
  initialDelaySeconds: 5
  periodSeconds: 10
```

`/healthz` is intentionally trivial. A *running* process is enough to
mark it live — anything that has crashed will not answer the socket.
Use `/readyz` (below) if you want the orchestrator to react to "running
but cannot serve" states.

## `/readyz` — readiness

Verifies the scan-store root exists, is a directory, and is writable.

```http
GET /readyz HTTP/1.1
```

Healthy response includes the resolved root path so a probe failure is
debuggable from the logs:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "scan_store_root": "/home/ag/.agentguardian/scans"
}
```

On failure the response is `503` with a typed reason verbatim from
[`server/routes/health.py:254-295`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L254-L295):

| Condition                                  | Status | Reason body                                                |
|--------------------------------------------|--------|------------------------------------------------------------|
| Root path does not exist                   | `503`  | `scan store root does not exist: <path>`                   |
| Root path is not a directory               | `503`  | `scan store root is not a directory: <path>`               |
| Root path is not writable by the process   | `503`  | `scan store root is not writable: <path>`                  |

```yaml
readinessProbe:
  httpGet:
    path: /readyz
    port: 7474
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 1
```

`failureThreshold: 1` because a non-writable scan store is a
not-going-to-self-recover condition — fail fast so the LB pulls the pod
out of rotation immediately.

## `/metrics` — Prometheus

```http
GET /metrics HTTP/1.1
```

`Content-Type: text/plain; version=0.0.4; charset=utf-8` (pinned at
[`server/routes/health.py:305-308`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L305-L308)).
The exposition is hand-rolled (no `prometheus_client` dep) so the
exact lines are predictable.

Six series, verbatim from the module docstring
([`server/routes/health.py:21-27`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L21-L27)):

| Metric                                                | Type       | Labels       |
|-------------------------------------------------------|------------|--------------|
| `agentguardian_scans_total`                           | counter    | —            |
| `agentguardian_scans_running`                         | gauge      | —            |
| `agentguardian_scan_duration_seconds`                 | histogram  | —            |
| `agentguardian_findings_total`                        | counter    | `severity`   |
| `agentguardian_llm_calls_total`                       | counter    | `provider`   |
| `agentguardian_llm_errors_total`                      | counter    | `provider`   |

Histogram bucket edges (seconds), verbatim from
[`server/routes/health.py:66-80`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L66-L80):

```text
0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0, 14400.0
```

`14400.0` (4 h) is the largest finite bucket. Scans longer than 4 h
still complete; their wall-clock count lands in the implicit `+Inf`
bucket (see [Performance](performance.md#scan-duration-ceiling)).

### Process-local, single-worker assumption

The counters are process-local and reset on restart. Verbatim from the
module docstring at
[`server/routes/health.py:30-31`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L30-L31):

> The counters are process-local and reset on restart — sufficient for
> the single-worker dashboard deployment that M12 ships. Multi-worker
> setups should aggregate in their LB or move to a Pushgateway.

If you scale `uvicorn --workers N > 1`, the counters fragment across
workers. Two production options:

1. front the deployment with a single replica and scale by
   running more replicas behind a stickier load balancer, or
2. push counters to a Pushgateway sidecar.

### Prometheus `scrape_config`

```yaml
scrape_configs:
  - job_name: agentguardian
    metrics_path: /metrics
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/agentguardian.token
    static_configs:
      - targets: ['dashboard.internal:7474']
```

The Bearer header is honoured by `/metrics` exactly the same way it
is on `/scans` — same `require_dashboard_auth` dependency.

## Reverse-proxy snippets

### Caddy

```caddy
dashboard.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:7474 {
        header_up X-Forwarded-For {remote_host}
        header_up Authorization {>Authorization}
    }
}
```

Caddy terminates TLS automatically (Let's Encrypt) and forwards the
`Authorization` header verbatim so Bearer auth still works.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name dashboard.example.com;
    ssl_certificate     /etc/letsencrypt/live/dashboard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dashboard.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:7474;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Authorization     $http_authorization;
        proxy_read_timeout 86400;          # SSE streams stay open for the scan
    }
}
```

The `proxy_read_timeout 86400` is the only non-default — the dashboard
SSE endpoint keeps a connection open for the full scan duration, so
the proxy's idle timeout must cover the largest scan you intend to run
(matches the 4 h Prometheus bucket ceiling).

## Minimal Kubernetes deployment

A working starting point — bind to all interfaces inside the pod, expose
on a `ClusterIP` service, wire both probes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentguardian
spec:
  replicas: 1
  selector:
    matchLabels: { app: agentguardian }
  template:
    metadata:
      labels: { app: agentguardian }
    spec:
      containers:
        - name: agentguardian
          image: agent-guardian:dev   # build locally; ghcr image is roadmap (see roadmap.md)
          args: ["serve", "--host", "0.0.0.0", "--port", "7474"]
          ports:
            - containerPort: 7474
          env:
            - name: AGENT_GUARDIAN_DASHBOARD_TOKEN
              valueFrom:
                secretKeyRef:
                  name: agentguardian-token
                  key: token
            - name: AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN
              valueFrom:
                secretKeyRef:
                  name: agentguardian-ingest
                  key: token
          livenessProbe:
            httpGet: { path: /healthz, port: 7474 }
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet: { path: /readyz, port: 7474 }
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 1
          volumeMounts:
            - mountPath: /home/ag/.agentguardian
              name: scans
      volumes:
        - name: scans
          persistentVolumeClaim:
            claimName: agentguardian-scans
---
apiVersion: v1
kind: Service
metadata:
  name: agentguardian
spec:
  selector: { app: agentguardian }
  ports:
    - port: 7474
      targetPort: 7474
```

The single replica is intentional — see the [process-local
note](#process-local-single-worker-assumption) above. For a multi-replica
deployment, sharded by scan-id, see [Performance](performance.md#single-worker-assumption).

## See also

- [Configuration](configuration.md) — full YAML schema for the server
  + swarm + budget sections.
- [Environment variables](env-vars.md) — the full env-var catalog for
  the dashboard and the rest of the CLI.
- [Deploy](deploy.md) — Docker / Compose / Kubernetes wiring with the
  same probes.
- [Observability](observability.md) — `/metrics` is the Prometheus side;
  `OTel` spans are the trace side. Both can run together.
- [Operator runbook](runbook.md) — symptom-cause-fix for the dashboard.
