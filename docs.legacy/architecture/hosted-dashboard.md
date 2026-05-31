# Hosted dashboard architecture

**Status:** Architecture captured. Not yet deployed.

AgentGuardian today ships a **local-only** dashboard. Every `agent-guardian scan`
emits a URL at `http://127.0.0.1:7474/scans/<id>` that points at the operator's
own machine; the dashboard process is a single-tenant uvicorn app and stores
state under `~/.agentguardian/scans/<id>/`.

This document specifies how a future **hosted SaaS dashboard** layers onto the
same scan binary without changing CLI ergonomics. The only knob the CLI needs
is the environment variable `AGENT_GUARDIAN_DASHBOARD_URL`. Everything else —
trust anchor, tenant model, auth, transport — lives behind that one base URL.

This is **forward-looking documentation**. There is no code in this repository
that talks to a hosted endpoint today.

## Goals

* Operators get a stable, shareable URL for a scan that survives the scan
  process exiting.
* Scan reports stay cryptographically verifiable end-to-end: the local CLI
  produces a signed bundle and the hosted side only renders bundles whose
  Ed25519 signature it can verify.
* Local-first is preserved: an operator who chooses not to publish never
  surfaces a single byte to the network.
* CLI surface is unchanged: no new flags beyond `--no-publish`. A `--publish`
  default to a hosted endpoint is selected via env, not CLI option churn.

## Non-goals

* Multi-tenancy on the **local** dashboard — local stays single-process,
  single-user.
* Real-time collaborative editing of scan reports.
* Hosting the swarm itself. The swarm runs on operator hardware; only the
  rendered report is published.

## Trust anchor

Every scan binary embeds a fingerprint for the AgentGuardian release public
key (used today to verify report signatures locally). The hosted side
maintains the same key registry — published as a static JSON manifest at
`/.well-known/agentguardian/keys.json`.

The render path on the hosted side is strict:

1. Receive a signed scan bundle (`scan.json` + detached signature +
   public-key id).
2. Look the key id up against the manifest. Unknown key → 403, scan never
   touches storage.
3. Verify the Ed25519 detached signature against the canonical JSON.
4. Persist the bundle. Render only what was in the verified payload.

The hosted side **does not** mutate the bundle. Findings, AIVSS, sub-scores,
ASI rows — all come from the signed payload. The hosted renderer is a
read-only formatter; it cannot synthesise or edit findings.

## Tenant model

Tenant = the entity that owns a publishing key.

| Concept | Storage | Example |
| --- | --- | --- |
| Tenant | `tenants/<tenant_id>` | `tenants/glacien` |
| Publishing key | `tenants/<id>/keys/<key_id>` | `tenants/glacien/keys/ed25519-2026-Q2` |
| Scan | `tenants/<id>/scans/<scan_id>` | `tenants/glacien/scans/cli-3a4c1d9c2840` |
| Member | `tenants/<id>/members/<user_id>` | (sets visibility ACL) |

Operators in a tenant either share a publishing key (simple) or hold their
own and have it admitted to the tenant key set (auditable). The CLI never
asks the operator to log in — it just signs the bundle and POSTs it. AuthN
of the operator happens *only* via the signature.

Visibility:

* **Private** (default) — only authenticated tenant members can render the
  scan URL.
* **Org-visible** — visible to a configured GitHub org / Google Workspace.
* **Public** — anyone with the URL can render. Operators opt in explicitly.

Scan URLs always carry an unguessable random suffix; the visibility flag
only relaxes the auth wall around them.

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
short-lived cookies for *viewers* of the URL — that's a browser-side
concern, not a CLI concern.

### CLI changes (for a future PR)

The implementation surface, when hosted lands, is exactly:

1. `agent-guardian scan` reads `AGENT_GUARDIAN_DASHBOARD_URL` and treats
   anything other than `http://127.0.0.1:*` or `http://localhost:*` as
   "hosted target". When hosted, after the scan completes:
   * Build a signed bundle (`scan.json` + signature + key id).
   * POST it to `${base_url}/v1/scans` with `Content-Type: application/zip`.
   * On 202, the body contains `{scan_url: "<base>/scans/<id>"}` and that
     replaces the local URL the CLI emitted at start.
   * On any non-202, fall back to local-only — the operator never loses the
     scan and gets a clear error message.
2. `--no-publish` already exists (this PR); it short-circuits the upload
   path. The operator keeps the scan locally.

No other CLI option churn. The locality pill in the dashboard chrome flips
from `Local` to `Hosted · evidence-signed` based on the effective base URL,
which already works today (template parameter, see
`src/agent_guardian/server/routes/scan.py`).

## URL pattern

| Surface | Pattern | Notes |
| --- | --- | --- |
| Local | `http://127.0.0.1:7474/scans/<id>` | default, no auth |
| Hosted, tenant-private | `https://dash.agentguardian.dev/scans/<id>` | random id, requires session |
| Hosted, public-share | `https://dash.agentguardian.dev/share/<token>` | tenant-issued, revocable |
| Report download | `https://dash.agentguardian.dev/scans/<id>/report.json` | signed canonical JSON |

The CLI only ever quotes `/scans/<id>` — the public-share URL is generated
later from the dashboard UI; the CLI does not know about it.

## Migration from local

Nothing forced. An operator running only `agent-guardian scan` against
`localhost:7474` today keeps doing exactly that. The hosted surface is
opt-in by **setting one env var**:

```bash
export AGENT_GUARDIAN_DASHBOARD_URL=https://dash.agentguardian.dev
agent-guardian scan --endpoint https://agent.example.com
```

When the env var points at a non-loopback host:

* The CLI emits the hosted URL at scan start (so the operator can share it
  before the scan finishes).
* The CLI publishes the signed bundle after the scan completes.
* The hosted dashboard renders the *same* templates as the local one
  (`templates/dashboard/scan_detail.html`) — only the chrome's locality
  pill changes (`Hosted · evidence-signed`).

When the env var is unset or points at loopback, the CLI behaves exactly
as it did before this work shipped.

## Roadmap (out of scope for this milestone)

* `agent-guardian models list` discovery command (referenced by QA-001's
  "did you mean" hint). The probe path's hard-coded suggestion map
  covers the common Gemini ids today; a discovery command is the proper
  long-term fix.
* Swarm centerpiece restyle (cyan → violet) at
  `src/agent_guardian/server/static/swarm.js`. The new editorial dashboard
  ships its own centerpiece partial that already uses violet; the legacy
  `swarm.js` continues to drive the standalone `/scan/<id>/swarm` page.
* Editorial findings copy (full italic prose with ATLAS/CSA tags) — the
  templates leave a `_findings_feed.html` slot; the prose author-pass is a
  separate workstream.
* Hosted Cloud Run deployment topology, IaC, and observability — beyond
  the docs scope of this PR.
