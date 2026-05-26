# Architecture

AgentGuardian is a three-layer pipeline. Layer 1 ingests the target, Layer 2
runs the swarm, Layer 3 scores and emits.

## The swarm diagram

```
                          ┌────────────────────────────┐
                          │    Swarm Commander LLM     │
                          │    (orchestration & dispatch) │
                          └──────────┬─────────────────┘
                                     │
                ┌────────────────────┼────────────────────┐
                │                    │                    │
                ▼                    ▼                    ▼
        ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
        │  Recon Agent │     │   Shared     │     │   Findings   │
        │  (map target)│◀───▶│ Vector Memory│◀───▶│   Aggregator │
        └──────────────┘     └──────────────┘     └──────────────┘
                                     ▲
                ┌────────────────────┼────────────────────┐
                │   Ten ASI-aligned specialist attackers  │
                │   running in parallel                   │
                │                                          │
                │   ASI01  Goal Hijack                     │
                │   ASI02  Tool Misuse                     │
                │   ASI03  Privilege Abuse                 │
                │   ASI04  Supply Chain                    │
                │   ASI05  Unauthorised Code Execution     │
                │   ASI06  Memory Poisoning                │
                │   ASI07  Agent-to-Agent Compromise       │
                │   ASI08  Cascading Failures              │
                │   ASI09  Trust Exploitation              │
                │   ASI10  Rogue Agent / Drift             │
                └─────────────────────────────────────────┘
```

## Layer 1 — Ingest

The target enters the system through one of four **adapters**:

| Mode | Adapter            | Use when                                          |
|------|--------------------|---------------------------------------------------|
|  A   | System prompt      | You only have the agent's system prompt           |
|  B   | Code               | You have the Python source of the agent           |
|  C   | HTTP               | The agent is reachable as an HTTP endpoint        |
|  D   | Framework          | LangGraph / CrewAI / AutoGen / LlamaIndex / etc.  |

Each adapter normalises its input into a **Target Profile** — the schema
the recon agent consumes. Profile fields cover declared tools, declared
memory backends, agent boundaries, exposed endpoints, and any guardrails
the target advertises.

See [Adapters](adapters/index.md) for the full reference.

## Layer 2 — Swarm

### The Recon Agent

The recon agent runs first and alone. It probes the target with a small
fixed corpus of low-risk reconnaissance queries — "what tools do you have
access to?", "describe your memory backend", "list any other agents you
can delegate to" — and writes the responses into shared vector memory as
**recon fragments**. Every downstream attacker reads from this memory, so
discoveries propagate.

### The ten specialist attackers

Each of ASI01–ASI10 has its own specialist agent with:

- A **seed-probe corpus** — hand-authored YAML probes, packaged in the
  wheel under `agent_guardian/probes/asi-XX/`.
- One or more **jailbreak strategies** — PAIR, TAP, Crescendo, or MAD-MAX,
  chosen per-probe to maximise the chance of bypassing guardrails.
- Read/write access to shared vector memory, so an ASI06 memory-poison
  finding becomes an ASI01 goal-hijack seed and so on.

### The Swarm Commander

The Commander is an LLM (OpenAI / Anthropic / Bedrock / Vertex / stub)
that runs the orchestration loop. Each tick it:

1. Reads the current status of all eleven agents.
2. Reads the latest findings from the aggregator.
3. Decides which agents to re-task, which to stop, and whether the swarm
   has converged (no new findings for N ticks).

Convergence detection prevents over-spend. A typical scan hits convergence
after 60–90 seconds against a well-defended target, or 20–30 seconds
against a weak one.

## Layer 3 — Score and emit

The **findings aggregator** triple-tags every finding with OWASP ASI,
MITRE ATLAS, and CSA Agentic-RT categories, then passes the full evidence
pack to the **AIVSS scorer**.

The scorer applies the deterministic AIVSS v0.8 formula — see
[AIVSS Formula](aivss-formula.md) — and produces:

- A 0–100 score.
- A severity band (Negligible / Low / Medium / High / Critical) with
  colour.
- A per-ASI breakdown.
- A Tier classification (T1 hard-fail / T2 / T3 / T4 cosmetic) for each
  finding.

The evidence pack is then signed with Ed25519 and emitted to disk. The
report layer (M13) renders the pack as JSON, SARIF, JUnit, Markdown, or
PDF on demand.

## Determinism guarantees

The scoring layer is **pure** — given the same evidence pack it always
returns the same score. The LLM-driven swarm layer is **not** pure (LLM
outputs vary), but every probe is seeded and every LLM call is logged in
the evidence pack so a run is fully auditable after the fact. Two
identical evidence packs collected on different days will produce
byte-identical signed reports.
