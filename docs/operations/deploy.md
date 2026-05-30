# Deploy

> **TL;DR.** Three deployment shapes — single-shot Docker scan, Docker
> Compose for the local dashboard, and a minimal Kubernetes manifest with
> probes wired. All examples are copy-paste correct against the repo's
> `Dockerfile` and `docker-compose.yml`.

The dashboard is the only long-lived component. The CLI is short-lived
by design — a `scan` is one process, one report, exit.

## Docker — single-shot scan

The bundled `Dockerfile` builds from the working source tree (no
GHCR image is published today — see [GHCR](#ghcr-image-roadmap) below).
The image includes the `[full]` extra so PDF report rendering works out
of the box.

```bash
git clone https://github.com/glacien-technologies/agent-guardian.git
cd agent-guardian
docker build -t agent-guardian:dev .

# Run one scan, mount the host cwd so the report lands locally.
docker run --rm -it \
  -e OPENAI_API_KEY \
  -v "$PWD":/work -w /work \
  agent-guardian:dev \
  scan --system-prompt prompt.txt --model openai:gpt-4o
```

The Dockerfile exposes `7474` for the dashboard subcommand; the scan
subcommand does not bind a port, so you can ignore it for single-shot
scans. See the [install guide](../tutorials/quickstart.md#1-install)
for the same recipe with provider-API-key wiring.

## Docker Compose — the dashboard

The repo ships a working `docker-compose.yml` at the root. It is the
fastest path to a local dashboard with persistent scan history:

```yaml
--8<-- "docker-compose.yml"
```

Bring it up and verify the three operational endpoints answer:

```bash
docker compose up -d
curl -sS http://localhost:7474/healthz
# {"status":"ok","version":"1.0.0"}
curl -sS http://localhost:7474/readyz
# {"status":"ok","version":"1.0.0","scan_store_root":"/home/ag/.agentguardian/scans"}
curl -sS http://localhost:7474/metrics | head -5
# # HELP agentguardian_scans_total Completed scans observed by the dashboard.
# # TYPE agentguardian_scans_total counter
# agentguardian_scans_total 0
# ...
```

!!! warning "The default compose binds publicly with no auth"
    The bundled `docker-compose.yml` ships `--host 0.0.0.0`. That makes
    the dashboard reachable on every interface of the Docker host —
    intentional for local-dev (so you can hit it from another
    container) but unsafe for anything else. **Before exposing the
    dashboard beyond your laptop**, set `AGENT_GUARDIAN_DASHBOARD_TOKEN`
    *and* front it with a reverse proxy that terminates TLS. See
    [Serving the dashboard](serve.md#authentication) for the full
    recipe.

To add auth in the compose file:

```yaml
    environment:
      - AGENT_GUARDIAN_LOG_LEVEL=info
      - AGENT_GUARDIAN_DASHBOARD_TOKEN=${DASHBOARD_TOKEN:?must be set}
      - AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN=${INGEST_TOKEN:?must be set}
```

`${VAR:?…}` fails the `docker compose up` if the var is unset —
treating "forgot to set the token" as an explicit configuration error
rather than silently shipping an open dashboard.

## GHCR image (roadmap)

```bash
docker pull ghcr.io/glacien-technologies/agent-guardian:<tag>
```

Not yet published. The build/publish workflow lands with v1.0.0 (see
the M15 line in [roadmap.md](../reference/roadmap.md) and the GHCR commentary
in the [Dockerfile](https://github.com/glacien-technologies/agent-guardian/blob/main/Dockerfile)).
Until then, build from source as above.

## Kubernetes

A minimal manifest that wires the dashboard with both probes and a
PVC for persistent scan history. Same shape as
[Serving the dashboard — minimal Kubernetes deployment](serve.md#minimal-kubernetes-deployment) —
duplicated here so the Deploy page is self-contained.

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: agentguardian-scans
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 10Gi
---
apiVersion: v1
kind: Secret
metadata:
  name: agentguardian-token
type: Opaque
stringData:
  token: REPLACE_WITH_OPENSSL_RAND_HEX_32
---
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
          image: agent-guardian:dev   # build locally; ghcr image is roadmap
          args: ["serve", "--host", "0.0.0.0", "--port", "7474"]
          ports:
            - containerPort: 7474
          env:
            - name: AGENT_GUARDIAN_DASHBOARD_TOKEN
              valueFrom:
                secretKeyRef:
                  name: agentguardian-token
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

The single `replicas: 1` is deliberate: `/metrics` counters are
process-local and `~/.agentguardian` is a `ReadWriteOnce` PVC. Both
constraints are documented in [Performance — single-worker
assumption](performance.md#single-worker-assumption).

## See also

- [Serving the dashboard](serve.md) — bind, auth, probes, reverse
  proxy.
- [Performance](performance.md) — sizing, single-worker constraint,
  in-memory buffer caps.
- [Operator runbook](runbook.md) — symptom-cause-fix on the running
  deployment.
- [Upgrade](upgrade.md) — in-place upgrade and rollback discipline.
