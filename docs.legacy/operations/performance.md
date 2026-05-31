# Performance

> **TL;DR.** Honest numbers, honest constraints. Measured wall-time +
> cost for FAST/SMART/FULL on Gemini, the single-worker assumption that
> the dashboard ships under, the in-memory event buffer that bounds
> per-scan RAM, and the tuning levers that actually move the needle.

## Measured numbers

The wall-time and cost numbers below are *measured*, not estimated, on
a single hardware + provider combination. They are reproduced verbatim
from [Scan modes — the three modes at a
glance](../concepts/scan-modes.md#the-three-modes-at-a-glance) so the
two pages cannot drift.

| Mode    | Probes per agent | Turns per agent | Measured wall | Measured cost (Gemini) |
|---------|------------------|-----------------|---------------|------------------------|
| `fast`  | top 3            | 4               | ~165 s        | ~$0.016                |
| `smart` | all              | 12              | ~190 s        | ~$0.019                |
| `full`  | all              | 12              | ~365 s        | ~$0.030                |

**Caveat — read this before you cite the numbers.** Run against the
OWASP-vulnerable-by-design target in
`agentguardian-benchmarks/targets/vulnerable/owasp_asi_all.py`, on
`gemini:gemini-2.5-flash`, on `2026-05-28`, **single run per mode**,
T2 tier. Other providers (OpenAI, Anthropic, Bedrock, Ollama) are
unmeasured. Your wall time will vary with target complexity, LLM
latency, and provider region; cost scales roughly linearly with
attacker + judge token volume. Do not quote these numbers as a
spec — they are a starting point for capacity planning.

## Single-worker assumption

The dashboard `/metrics` exposition is process-local. Verbatim from
the module docstring at
[`server/routes/health.py:30-31`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L30-L31):

> The counters are process-local and reset on restart — sufficient for
> the single-worker dashboard deployment that M12 ships. Multi-worker
> setups should aggregate in their LB or move to a Pushgateway.

Two practical implications:

1. If you run `uvicorn --workers N > 1`, your counters fragment.
   Aggregate at the load balancer or write to a Pushgateway.
2. If you scale to N pods behind a load balancer, the same applies.

The scan store is also single-process — running scans are registered
in an in-memory dict on `app.state.scan_store`, and the SSE queue is
an `asyncio.Queue`. Multiple workers will not share state. A future
release can swap the in-memory queue for Redis if multi-worker is
needed; today the bound is one process.

## Scan duration ceiling

The Prometheus histogram's largest finite bucket is `14400.0` seconds
(4 hours), enumerated at
[`server/routes/health.py:65,79`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/routes/health.py#L65-L79). Scans longer than 4 hours **still
complete** — their wall-clock observation simply lands in the implicit
`+Inf` bucket per Prometheus convention. Be aware that a histogram
quantile derived from this exposition treats anything above 4 h as
indistinguishable.

If you regularly run scans longer than 4 h, either:

- accept the `+Inf` rollup and observe wall-time elsewhere
  (e.g. trace duration on the `invoke_agent` parent span), or
- patch `_DEFAULT_DURATION_BUCKETS` locally and rebuild.

## In-memory event buffer

The scan store keeps one in-memory `collections.deque` per running
scan, capped at `MAX_BUFFERED_EVENTS_PER_SCAN` = 5000 by default.
Cite
[`server/scan_store.py:73-102`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L73-L102).

Override via env var:

```bash
export AGENT_GUARDIAN_MAX_BUFFERED_EVENTS=20000   # ints only; non-positive falls back to 5000
```

The deque is a ring buffer — once full, the *oldest* event is evicted.
The on-disk `events.jsonl` file
([`server/scan_store.py:99-102`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L99-L102))
is the **authoritative replay source**: every event is flushed to it
before the in-memory copy is created. Late SSE subscribers within the
300 s grace window
([`server/scan_store.py:108`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L108))
get an in-memory replay; subscribers beyond the window read from disk.

When the SSE queue (separate from the deque) is full, the producer
logs a `WARNING` at
[`server/scan_store.py:243`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/server/scan_store.py#L243):

```text
scan_store: SSE queue full for <scan_id> — dropping <kind> event
```

That overflow is **not yet exposed as a Prometheus counter**. A
candidate `agentguardian_events_dropped_total{reason}` series is
tracked as future work in [roadmap.md](../reference/roadmap.md). Until then,
grep the structured log JSON for `"event": "scan_store: SSE queue
full"` to alert on the condition. See [Operator
runbook — buffer-cap drops](runbook.md#buffer-cap-drops) for the
runbook entry.

## Host sizing

Observed, not promised. One single in-flight FULL scan on Gemini
2.5 Flash plus the dashboard runs comfortably in ~2 vCPU and ~4 GiB
of RAM. PDF rendering through WeasyPrint peaks higher — pango/cairo
fonts are not free.

| Workload                                  | vCPU | RAM    |
|-------------------------------------------|------|--------|
| Dashboard idle                            | <0.1 | ~150 MiB |
| One in-flight FULL scan + dashboard       | ~2   | ~4 GiB   |
| WeasyPrint PDF render (peak)              | spike | +500 MiB transient |
| FAST mode, parallel scans                 | scales linearly with `max_parallel_agents` |

Measure your own — workload skew on the attacker model and target
latency dominate. These are starting points, not SLOs.

## Tuning levers

The four knobs that actually move scan wall-time / cost / coverage:

1. **`budget.wall_seconds`** in the contract or YAML config. The
   commander stops cleanly at this cap. The CLI flag is implicit (no
   per-flag override today) — set it in `agentguardian.yaml`. See
   [Configuration — `swarm`](configuration.md#swarm).
2. **`--mode fast | smart | full`**. The biggest single lever — see
   the [Measured numbers](#measured-numbers) table.
3. **`max_parallel_agents`** in `swarm:` config. Lower this when you
   are rate-limited at the provider; higher does not help until you
   are wall-clock-bound rather than turn-bound. With `--owasp-llm`
   active the cap is overridden to 14 (see
   [Configuration — `swarm.max_parallel_agents`](configuration.md#swarm)
   for the divergence).
4. **`--budget-usd`** soft-stops new attack turns at 80 % of the cap
   and reserves the remainder for the report. Useful as a per-CI-run
   guard; not useful as a tuning knob in itself.

## See also

- [Concepts — scan modes](../concepts/scan-modes.md) — full mode
  breakdown.
- [Configuration](configuration.md) — the YAML knobs cited above.
- [Operator runbook — OOM during full-mode scan](runbook.md#oom-during-a-full-mode-scan)
  — symptom-cause-fix for the most common memory complaint.
- [Serving the dashboard — process-local single-worker
  assumption](serve.md#process-local-single-worker-assumption) — the
  same constraint, viewed from the metrics scrape side.
