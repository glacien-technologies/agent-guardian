# Telemetry transparency

AgentGuardian Open ships with **essential-tier telemetry on by default** and an explicit opt-out. This page is the canonical reference for what's collected at each tier, what's NEVER collected, how to audit it, and how to disable it.

Per [Engineering Standards §9.4](../engineering-standards.md), the telemetry source code is shipped *in the package* so anyone can read it before opting out or upgrading. The aggregator that runs on Glacien infrastructure is also in the package, so you can self-host the collector for testing.

## TL;DR

| Question | Answer |
|---|---|
| Is telemetry on by default? | **Yes — essential tier.** Only operational counts: agents fired, attempts, successes, threats captured, AIVSS, crash status, duration, anonymous install_id. **No environment fingerprint.** |
| Why on-by-default? | A security tool needs to publish "X scans run / Y threats caught / Z% crash-free" to be credible. Default-off means the public dashboard never has data; default-on with a strict allowlist gives the community something real to look at. |
| What's the worst thing the ESSENTIAL tier could leak? | An anonymous count of how many scans you ran and what their AIVSS scores were. It cannot identify you, your machine, your code, your prompts, your findings, your file paths, your IP, or your environment. |
| How do I turn it off? | `agent-guardian telemetry disable` — this also sends a `forget` event so your install_id is deleted server-side. |
| How do I share MORE (environment matrix)? | `agent-guardian telemetry extended` — adds adapter / Python version / OS / arch. Helps the per-framework + Python×OS dashboard cells populate. |
| How do I see exactly what would be sent? | `agent-guardian telemetry show` — or read [`src/agent_guardian/telemetry/events.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/telemetry/events.py). |
| How do I start fresh? | `agent-guardian telemetry reset` — clears consent + install_id + local buffer; first scan after reset prints the notice again. |

## The three tiers

| Tier | Default | Sends operational counts | Sends environment fingerprint | CLI |
|---|---|---|---|---|
| **OFF** | no | — | — | `telemetry disable` |
| **ESSENTIAL** | **yes — first scan prints a one-line notice** | yes | **no** | `telemetry essential` |
| **EXTENDED** | no | yes | yes (adapter / Python / OS / arch) | `telemetry extended` |

## What's collected (the entire allowlist)

Three event types exist. `scan_completed` fires per scan; `install` fires once when the notice prints; `forget` fires when the user opts out.

### `scan_completed` — one per scan

Fields are tagged **🟢 ESSENTIAL** (always sent unless disabled) or **🟡 EXTENDED** (only sent on the extended tier).

| Tier | Field | Example | What it's used for |
|---|---|---|---|
| 🟢 | `install_id` | `0bd84c9d-…` (UUID4) | Counting distinct installs |
| 🟢 | `scan_id` | `aaaa1111…` (random hex) | Deduplication only |
| 🟢 | `aivss` | `84` | The AIVSS distribution histogram |
| 🟢 | `band` | `GOOD` | Band-distribution percentages |
| 🟢 | `tier` | `T3` | Median scan time by tier |
| 🟢 | `duration_seconds` | `82.5` | Scan duration percentiles |
| 🟢 | `terminated_by` | `success` / `error` / `crash` | **Crash-free rate** |
| 🟢 | `agents_count` | `9` | **Number of swarm agents that ran** |
| 🟢 | `attempts_count` | `68` | **Total per-turn judged events (attempts tried)** |
| 🟢 | `successes_count` | `63` | **Per-turn pass verdicts (target defended)** |
| 🟢 | `findings_total` | `5` | **Threats captured (per scan)** |
| 🟢 | `findings_critical/_high/_medium/_low` | `1/2/1/1` | Severity distribution |
| 🟢 | `agent_version` | `1.0.0` | Crash rate per release |
| 🟢 | `started_at` / `completed_at` | ISO-8601 UTC | Time-windowed aggregation |
| 🟡 | `adapter` | `langgraph` | Adapter usage mix dashboard cell |
| 🟡 | `target_mode` | `code` | Mode distribution |
| 🟡 | `python_version` | `3.11` | Python × OS compatibility matrix |
| 🟡 | `os_family` | `Darwin` / `Linux` / `Windows` | Compatibility matrix |
| 🟡 | `arch` | `arm64` / `x86_64` | Compatibility matrix |

The four operational counts (`agents_count`, `attempts_count`, `successes_count`, `findings_total`) are exactly the "number of agents, number of attempts, successes, threats captured" set the project owner explicitly designated as on-by-default. They cannot identify you — they are scan-level aggregates over an opaque scan_id.

### `install` — fires once when you opt in

The same environment fields as `scan_completed`, plus `opted_in_at`. Used so the collector can attribute MAU correctly even if a user opts in then never runs a scan.

### `forget` — fires once when you opt out

Just `install_id` + `opted_out_at`. Tells the collector to drop the row for your install_id.

## What is NEVER collected

The allowlist is enforced by Pydantic `extra="forbid"` — any code path that tries to add a field outside the list above will raise at construction time, not silently leak. Specifically forbidden:

- Prompts, model responses, judge transcripts, finding text.
- File paths, hostnames, IP addresses.
- Environment variable names or values.
- LLM provider API keys.
- Your username, email, GitHub handle, organisation.
- Probe seed text (per-probe events arrive in v1.1 with `probe_id` only — never seed contents).
- Stack traces (exception classes only, in v1.1 behind a second toggle).
- Geographic precision beyond country-top-25 (and even country only via PyPI BigQuery, not via telemetry).

## How aggregation respects your privacy

Every public cell on `agentguardian.ai/analytics` enforces **k ≥ 50** — the metric is suppressed (shown as `—`) unless at least 50 distinct `install_id`s contribute to that bucket. So:

- Until 50+ people opt in, the median AIVSS is hidden.
- Until 50+ people run on macOS Python 3.13, that cell of the matrix is hidden.
- Until 50+ people on Strands, the Strands row of the adapter table is hidden.

This is the same k-anonymity principle used by Homebrew analytics. It means an attacker can't correlate "is install_id X the user who ran scan Y on adapter Z" because the cell containing them never publishes.

## How to audit before opting in

```sh
# Read the data contract.
cat src/agent_guardian/telemetry/events.py

# Read what gets sent.
agent-guardian telemetry show

# Read the collector source — this is what runs at telemetry.agentguardian.ai.
cat src/agent_guardian/server/analytics/store.py
cat src/agent_guardian/server/analytics/aggregator.py

# Read the route that handles ingestion.
cat src/agent_guardian/server/routes/analytics.py

# Self-host the collector to verify behaviour:
AGENT_GUARDIAN_TELEMETRY_URL=http://127.0.0.1:7474/api/telemetry/v1/events \
  AGENT_GUARDIAN_ANALYTICS_DB=/tmp/audit.db \
  agent-guardian serve
# Then: agent-guardian telemetry enable && agent-guardian scan ...
# Then inspect the SQLite at /tmp/audit.db.
```

## Configuration

| Environment variable | Purpose | Default |
|---|---|---|
| `AGENT_GUARDIAN_TELEMETRY_URL` | Where the client POSTs events | `https://telemetry.agentguardian.ai/v1/events` |
| `AGENT_GUARDIAN_HOME` | Where consent + install_id + local buffer live | `~/.agentguardian` |
| `AGENT_GUARDIAN_ANALYTICS_DB` | Collector backend (server-side) | `~/.agentguardian/analytics.db` (reference SQLite) |

## CLI surface

```
agent-guardian telemetry essential   # switch to ESSENTIAL tier (default)
agent-guardian telemetry extended    # upgrade to EXTENDED tier
agent-guardian telemetry disable     # OPT OUT + send ForgetEvent
agent-guardian telemetry status      # current state + pending buffer
agent-guardian telemetry show        # print the full schema (what would be sent)
agent-guardian telemetry reset       # clear consent + install_id + buffer + re-show notice
agent-guardian telemetry enable      # legacy alias of `extended` (v1.0rc1 compat)
```

## Failure modes

- **Collector unreachable.** Events buffer to `~/.agentguardian/local.db`. The user's CLI exit code is never affected.
- **HTTP 4xx from collector.** The envelope is dropped (it's a schema mismatch — retrying won't help) and logged.
- **HTTP 5xx from collector.** The envelope stays buffered; retry on next emit.
- **Clock skew.** Events with `client_sent_at` more than 30 days past or 5 minutes future are rejected by the collector and not persisted.
- **You opt out then opt back in.** A new install_id is generated; the old one is `forget`-ed.

## Related documents

- [Engineering Standards §9.4 — Telemetry transparency commitments](../engineering-standards.md)
- [`docs/security/disclosure-history.md`](../security/disclosure-history.md) — if you find a telemetry leak, report it here
- [`SECURITY.md`](../../SECURITY.md) — vulnerability disclosure policy
