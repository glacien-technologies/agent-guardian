# Run the dashboard with Docker Compose

**TL;DR.** The repo ships a one-service `docker-compose.yml` that builds the dashboard image and exposes it on `localhost:7474`. Useful when you don't want to install Python locally — or when you want a disposable dashboard for a CI demo. Read the warning below before exposing it past loopback.

## Prerequisites

- Docker 20.10+ and Docker Compose v2 (`docker compose ...`, not the legacy `docker-compose` binary).
- The repo cloned locally so Compose can find the `Dockerfile`.

## The compose file

Live file at the repo root: [`docker-compose.yml`](https://github.com/glacien-technologies/agent-guardian/blob/main/docker-compose.yml).

```yaml
--8<-- "docker-compose.yml"
```

A single service:

- Builds from the repo-root `Dockerfile`.
- Maps host `7474` -> container `7474` (the dashboard's default port).
- Mounts `./.agentguardian` on the host into `/home/ag/.agentguardian` in the container, so scan history and signing keys persist across `docker compose down`.
- Runs `agent-guardian serve --host 0.0.0.0 --port 7474` — note the `0.0.0.0` bind below.

## Start it

```bash
docker compose up -d
```

Confirm both endpoints are live before you point a browser at it:

```bash
curl -fsS http://localhost:7474/healthz
curl -fsS http://localhost:7474/readyz
```

`/healthz` is liveness — returns `{"status":"ok","version":...}`. `/readyz` is readiness — verifies the scan store root is writable. Both are documented in [`src/agent_guardian/server/routes/health.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py).

Then open <http://localhost:7474> in a browser.

## Tail logs

```bash
docker compose logs -f agentguardian
```

## Stop it

```bash
docker compose down
```

State (scan history, signing keys) is preserved on the host under `./.agentguardian` and will be picked up on the next `up`.

!!! warning "The compose file binds `0.0.0.0:7474` with no auth"
    The shipped compose file runs `serve --host 0.0.0.0` so the dashboard is reachable from the Docker host's network — that's what you want on a laptop, but it's **not** safe to expose unmodified to a LAN, a VPS public interface, or a public IP.

    Before exposing it past loopback, **always** set both:

    - `AGENT_GUARDIAN_DASHBOARD_TOKEN` — the bearer token required to read scan history.
    - `AGENT_GUARDIAN_DASHBOARD_INGEST_TOKEN` — the bearer token required to POST scan events.

    Both env vars are documented in [Operations - Environment variables](../operations/env-vars.md#dashboard-server). Add them under `environment:` in the compose file. For production also front the service with a reverse proxy that terminates TLS and bind the container's host port to `127.0.0.1` (`"127.0.0.1:7474:7474"`) so only the proxy can reach it. See [Operations - Serve in production](../operations/serve.md) for the full hardening list.

## Customise the model

The bundled compose recipe runs the dashboard against the deterministic stub backend. To use a real LLM, add the credential as a compose environment entry and pass `--model` on the scan command:

```yaml
    environment:
      - AGENT_GUARDIAN_LOG_LEVEL=info
      - OPENAI_API_KEY=sk-...
```

See [LLM providers](../integrations/providers/index.md) for the full set.

## What next

- Deploy somewhere other than your laptop: [Operations - Deploy with Docker](../operations/deploy.md).
- Run the dashboard under a real reverse proxy: [Operations - Serve in production](../operations/serve.md).
- All env vars the container respects: [Operations - Environment variables](../operations/env-vars.md).
