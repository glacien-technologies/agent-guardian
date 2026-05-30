# Operator runbook

> **TL;DR.** Symptom → cause → fix for the six failure modes operators
> hit most. Every cause and every fix cites a file:line so you can
> verify the runbook matches the running code.

The pattern below is the same for every entry: the surface symptom you
see in logs / exit code, the root cause traced into source, and the
remediation. Use the table of contents on the right to jump.

## Provider 429 / rate-limit

### Symptom

```text
WARNING: retry 3/6 (LLMRateLimitError: <provider>: 429 Too Many Requests) — backoff 8.42s
...
WARNING: retry exhausted after 6 attempts: LLMRateLimitError: <provider>: 429 Too Many Requests
```

The CLI exits with `EXIT_LLM_PROVIDER` (`4`) — see [FAQ — exit
codes](../faq/index.md#what-do-the-exit-codes-mean).

### Cause

`with_backoff` retries any `LLMRateLimitError` /
`LLMTransientError` / `LLMTimeoutError`. The defaults at
[`llm/retry.py:136-148`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/retry.py#L136-L148):

- `base_seconds=1.0`, `factor=2.0`, `max_seconds=60.0`,
  `max_retries=6` for one-off provider calls.
- `AGENT_LOOP_MAX_RETRIES=3`, `AGENT_LOOP_MAX_SECONDS=15.0` for the
  agent loop (cite
  [`llm/retry.py:51-52`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/retry.py#L51-L52)).

The provider's `Retry-After` header is honoured verbatim when
present — see
[`llm/retry.py:189-192`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/retry.py#L189-L192).
When the budget is exhausted the exception is surfaced as
`LLMRateLimitError` → exit code `4`.

### Fix

1. **Drop `max_parallel_agents` to `5`** in `agentguardian.yaml`
   ([`config.py:54`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/config.py#L54))
   when a tier is permanently throttled. Halves concurrent provider
   load.
2. Move to a higher provider tier or swap to a cheaper model on the
   attacker / evaluator roles
   ([`--attacker-model` / `--evaluator-model`](../reference/cli.md#options)).
3. If 429s are sporadic (peak hours), keep the defaults — the
   exponential backoff with 0.25 jitter (cite
   [`llm/retry.py:60`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/llm/retry.py#L60))
   absorbs short bursts.

## Target endpoint unreachable mid-scan

### Symptom

```text
ERROR: target unreachable: ConnectionRefusedError: ...
```

Two distinct sub-cases depending on **when** the unreachability
appears:

| When                          | Exit code                                                                                      | Outcome                                                                                              |
|-------------------------------|------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| At start (pre-flight)         | `EXIT_TARGET_UNREACHABLE` (`3`) — see [FAQ — exit codes](../faq/index.md#what-do-the-exit-codes-mean) | The scan never started; pre-flight stopped at the `connect` stage.                                   |
| Mid-scan                      | Scan completes; per-turn errors land as evidence                                               | Each failed turn is recorded so the report shows the moment the target went away; no spurious abort. |

### Cause

The contract pre-flight stops at the first failing stage
(see [`contract/preflight.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/contract/preflight.py)
and `agent-guardian validate` in
[CLI reference — `validate`](../reference/cli.md#validate)). Mid-scan failures
are tolerated by the agent loop — they degrade individual turns,
not the whole scan — so the report reflects partial coverage rather
than failing outright.

### Fix

1. Run `agent-guardian validate ./agentguardian.yaml` against the
   contract first; fix any stage that fails.
2. Check the target health endpoint and your network path to it
   (firewalls, mTLS).
3. If the mid-scan failures are intermittent, re-run with a smaller
   `--mode` (cuts the scan duration; reduces exposure to flakes) or
   increase `budget.wall_seconds` so the swarm has time to retry.

## Dashboard process crashed

### Symptom

The `agent-guardian serve` process exits unexpectedly. SSE clients
disconnect; new scans cannot register.

### Cause

Whatever made it crash. **What survives the crash:** every event the
scan store has accepted is `flush()`-ed to `events.jsonl` per event,
cite
[`server/scan_store.py:251-260`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L251-L260) — so the on-disk replay is
authoritative. **What is lost:** the in-memory deque
([`server/scan_store.py:230-234`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L230-L234)) and the open SSE queues; subscribers
have to reconnect.

### Fix

1. Restart the process under a supervisor that auto-restarts:
   `systemd`, `supervisord`, the Kubernetes `restartPolicy: Always`.
2. The scan store rehydrates on restart from
   `~/.agentguardian/scans/{id}/`:
   - `_index.json` — paginated history index
   - `scan.json` — the final signed `Scan` payload (when the scan
     finished cleanly)
   - `events.jsonl` — append-only event log for replay
3. Long-running scans that crashed mid-flight will show up in the
   dashboard as completed-with-partial-evidence on restart (the
   `agent_done` event for any in-flight specialist was never written,
   so its row stays at "running"; manual cleanup is the runbook for
   that — `agent-guardian` does not yet ship a `gc` command).

## OOM during a full-mode scan

### Symptom

```text
MemoryError
```

or the OS OOM-killer reaps the process. Most visible on long
`--mode full` scans against high-cardinality targets.

### Cause

Three contributing factors, all bounded:

1. **The in-memory event deque** — capped at 5000 per scan (see
   [Performance — in-memory event buffer](performance.md#in-memory-event-buffer)).
   Override via `AGENT_GUARDIAN_MAX_BUFFERED_EVENTS`.
2. **The 4 h Prometheus bucket ceiling** — scans longer than 4 h
   complete but their wall-time lands in `+Inf`; the swarm itself does
   not allocate proportional to runtime, but the open scan-store
   deque does. See
   [Performance — scan duration ceiling](performance.md#scan-duration-ceiling).
3. **The contract `budget.wall_seconds`** — the swarm stops cleanly
   at this cap. Set it to a realistic value for your target rather
   than letting an unbounded scan eat memory.

### Fix

1. Set `budget.wall_seconds: 1800` (30 min) in
   `agentguardian.yaml` to bound the worst case
   ([Configuration — `swarm`](configuration.md#swarm)).
2. Lower `AGENT_GUARDIAN_MAX_BUFFERED_EVENTS` to `2000` if you do not
   need full replay history in the dashboard.
3. Provision more RAM — see
   [Performance — host sizing](performance.md#host-sizing). The
   measured baseline for one FULL scan plus dashboard is ~4 GiB; if
   you are below that, the OS is not lying to you.

## Buffer-cap drops

### Symptom

```text
WARNING scan_store: SSE queue full for <scan_id> — dropping <kind> event
```

### Cause

The SSE consumer (a browser tab or programmatic subscriber) has
fallen behind the producer. The per-scan `asyncio.Queue` rejected a
`put_nowait`, and the producer logged at
[`server/scan_store.py:243`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L243).
The event has still been written to `events.jsonl`; only the live
SSE delivery to that one slow subscriber was dropped.

### Fix

1. Reload the dashboard tab so SSE re-subscribes and reads from the
   in-memory replay (within the 300 s grace window per
   [`server/scan_store.py:108`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L108))
   or from `events.jsonl` (beyond the window).
2. For programmatic subscribers, debug the consumer. The producer
   never blocks waiting on a slow subscriber by design.

### Caveat — no Prometheus counter today

There is **no** `agentguardian_events_dropped_total` counter exposed
at `/metrics` yet. The condition is observable only in the structured
logs. A roadmap candidate counter is tracked in
[roadmap.md](../reference/roadmap.md). Until then, alert on the JSON log line:

```jq
.event == "scan_store: SSE queue full for"
```

## Report generation failure (WeasyPrint dies)

### Symptom

```text
report write error: PdfFeatureUnavailable: WeasyPrint not importable
```

The CLI exits `EXIT_CONFIG` (`2`) — see
[FAQ — `agent-guardian` says "PDF engine not available"](../faq/index.md#pip-install-agent-guardianfull-fails-on-weasyprint-native-deps).

### Cause

WeasyPrint depends on native pango / cairo / harfbuzz / jpeg libs
that are not in the base wheel. On macOS the workaround is `brew
install pango cairo harfbuzz`; in containers it is the apt-get block
in the [`Dockerfile`](https://github.com/glacien-technologies/agent-guardian/blob/main/Dockerfile).
ReportLab is a lighter fallback (`pip install
'agent-guardian[pdf-fallback]'`).

### Fix — and what is preserved

The per-format writers are persisted independently under
`~/.agentguardian/scans/{id}/report.*`
([`server/scan_store.py:810-824`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L810-L824)).
A PDF render failure does **not** invalidate the other outputs — the
JSON, SARIF, JUnit, and Markdown reports already wrote successfully
before the PDF writer ran.

1. Install a PDF engine (WeasyPrint or ReportLab) per the
   [FAQ](../faq/index.md#pip-install-agent-guardianfull-fails-on-weasyprint-native-deps).
2. Re-render PDF only:
   `agent-guardian report <SCAN_ID> --output pdf --output-path
   report.pdf`. Existing JSON / SARIF / JUnit / MD reports are
   untouched.
3. As a one-line confirmation that PDF is wired:
   `python -c "import agent_guardian; print(agent_guardian.available_pdf_engines())"`.

## See also

- [Serving the dashboard](serve.md) — bind, auth, health endpoints.
- [Performance](performance.md) — the buffer caps and single-worker
  constraint cited above.
- [Observability](observability.md) — JSON log schema for parsing
  the warning lines above.
- [Upgrade](upgrade.md) — when to roll back if a release introduces a
  regression.
- [FAQ — exit codes](../faq/index.md#what-do-the-exit-codes-mean) —
  the table that every exit code in this runbook maps back to.
