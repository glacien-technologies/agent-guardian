# Hosted dashboard architecture

**Status:** Architecture captured. Not yet deployed.

AgentGuardian today ships a **local-only** dashboard. Every
`agent-guardian scan` emits a URL at
`http://127.0.0.1:7474/scans/<id>` that points at the operator's own
machine; the dashboard process is a single-tenant uvicorn app and
stores state under `~/.agentguardian/scans/<id>/`.

This document specifies how a future **hosted SaaS dashboard** layers
onto the same scan binary without changing CLI ergonomics. The only
knob the CLI needs is the environment variable
`AGENT_GUARDIAN_DASHBOARD_URL`. Everything else — trust anchor, tenant
model, auth, transport — lives behind that one base URL.

This is **forward-looking documentation**. There is no code in this
repository that talks to a hosted endpoint today.

Coming soon: a fully-rendered version of this page lives in
[`docs/architecture/live-dashboard.mdx`](./live-dashboard.mdx). This
`.md` placeholder pins the legacy URL (`architecture/hosted-dashboard.md`)
so external links keep resolving and so the architecture-presence test
can guard against silent doc loss.

## Trust anchor

Every scan binary embeds a fingerprint for the AgentGuardian release
public key (used today to verify report signatures locally). The
hosted side maintains the same key registry — published as a static
JSON manifest at `/.well-known/agentguardian/keys.json`.

The render path on the hosted side is strict:

1. Receive a signed scan bundle (`scan.json` + detached signature +
   public-key id).
2. Look the key id up against the manifest. Unknown key → `403`, scan
   never touches storage.
3. Verify the Ed25519 detached signature against the canonical JSON.
4. Persist the bundle. Render only what was in the verified payload.

The hosted side **does not** mutate the bundle. Findings, AIVSS,
sub-scores, ASI rows — all come from the signed payload. The hosted
renderer is a read-only formatter; it cannot synthesise or edit
findings.

## Tenant model

A tenant is the entity that owns a publishing key.

| Concept | Storage | Example |
| --- | --- | --- |
| Tenant | `tenants/<tenant_id>` | `tenants/glacien` |
| Publishing key | `tenants/<id>/keys/<key_id>` | `tenants/glacien/keys/ed25519-2026-Q2` |
| Scan | `tenants/<id>/scans/<scan_id>` | `tenants/glacien/scans/cli-3a4c1d9c2840` |
| Member | `tenants/<id>/members/<user_id>` | (sets visibility ACL) |

Operators in a tenant either share a publishing key (simple) or hold
their own and have it admitted to the tenant key set (auditable). The
CLI never asks the operator to log in — it just signs the bundle and
POSTs it. AuthN of the operator happens *only* via the signature.

Visibility:

* **Private** (default) — only authenticated tenant members can render
  the scan URL.
* **Org-visible** — visible to a configured GitHub org / Google
  Workspace.
* **Public** — anyone with the URL can render. Operators opt in
  explicitly.

Scan URLs always carry an unguessable random suffix; the visibility
flag only relaxes the auth wall around them.

## Auth flow

```
operator                       agent-guardian CLI            hosted dashboard
   │                                  │                              │
   │  agent-guardian scan ...         │                              │
   │  AGENT_GUARDIAN_DASHBOARD_URL=…  │                              │
   │ ────────────────────────────────►│                              │
   │                                  │ 1. run swarm locally         │
   │                                  │ 2. sign scan.json (Ed25519)  │
   │                                  │ 3. POST {bundle}             │
   │                                  │ ────────────────────────────►│
   │                                  │                              │ verify sig
   │                                  │                              │ store bundle
   │                                  │ ◄────────────────────────────│
   │                                  │   202 {scan_url}             │
   │ ◄────────────────────────────────│                              │
   │  ▸ Scan cli-3a4c1d9c2840 — …     │                              │
   │  ▸ Report when complete  …       │                              │
```

The CLI authenticates only with the signature. The hosted side issues
short-lived cookies for *viewers* of the URL — that is a browser-side
concern, not a CLI concern.

## Migration from local

Nothing forced. An operator running only `agent-guardian scan` against
`localhost:7474` today keeps doing exactly that. The hosted surface is
opt-in by setting one environment variable:

```bash
export AGENT_GUARDIAN_DASHBOARD_URL=https://dash.agentguardian.dev
agent-guardian scan --endpoint https://agent.example.com
```

When the env var points at a non-loopback host:

* The CLI emits the hosted URL at scan start (so the operator can
  share it before the scan finishes).
* The CLI publishes the signed bundle after the scan completes.
* The hosted dashboard renders the *same* templates as the local one
  (`templates/dashboard/scan_detail.html`) — only the chrome's
  locality pill changes (`Hosted · evidence-signed`).

When the env var is unset or points at loopback, the CLI behaves
exactly as it did before this work shipped.
