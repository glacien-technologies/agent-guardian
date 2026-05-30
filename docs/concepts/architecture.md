# Architecture

!!! abstract "TL;DR"
    Three layers — ingest → swarm → score. The swarm runs 1 recon + 10 ASI + the OWASP-LLM specialist set by default (capped at 14 parallel agents). Read this after the [quickstart](../tutorials/quickstart.md), before you wire it into your own code.

## The three layers

```
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 1 — INGEST                                                     │
│   prompt / code / http / framework adapter  →  TargetAdapter         │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 2 — SWARM                                                      │
│   Commander LLM                                                      │
│        │                                                             │
│        ├─► Recon agent              (maps tools / memory / PII)      │
│        ├─► 10 ASI specialists       (ASI01–ASI10, one per category)  │
│        └─► OWASP-LLM specialists    (fuzzing, secret-extraction,     │
│                                      denial-of-wallet, detection-    │
│                                      evasion, output-handling)       │
│        │                                                             │
│        ▼                                                             │
│   Shared vector memory  ◄──►  MAD-MAX racing  ◄──►  Findings buffer  │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 3 — SCORE & EMIT                                               │
│   compute_aivss() → AIVSS 0–100 + per-ASI + sub-scores               │
│   sign with Ed25519 + HMAC-SHA256                                    │
│   emit Scan JSON / SARIF 2.1.0 / JUnit / Markdown / PDF              │
└──────────────────────────────────────────────────────────────────────┘
```

## Layer 1 — Ingest

The target enters the system through one of four **adapters**:

| Mode | Adapter            | Use when                                                     |
|------|--------------------|--------------------------------------------------------------|
|  A   | System prompt      | You only have the agent's system prompt                      |
|  B   | Code               | You have the Python source of the agent (`async def run`)    |
|  C   | HTTP               | The agent is reachable as an HTTP endpoint                   |
|  D   | Framework          | LangGraph / CrewAI / AutoGen / OpenAI Agents / Strands / ADK |

Each adapter normalises its input into a `TargetAdapter` instance whose `TargetFingerprint` the recon agent then refines. Adapter detail in [Adapters](../integrations/adapters/index.md).

## Layer 2 — The specialist attackers

The default scan from `agent-guardian scan` instantiates the recon agent, the ten ASI specialists, and the five OWASP-LLM specialists from `M2_SPECIALIST_AGENTS` — 16 candidate agent classes, capped at 14 running in parallel:

| #  | Agent                       | ASI scoring slot | Source                                                                                                            |
|----|-----------------------------|------------------|-------------------------------------------------------------------------------------------------------------------|
| 1  | `recon-agent`               | n/a              | [`agents/recon.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/recon.py) |
| 2  | `goal-hijack-agent`         | ASI01            | [`agents/goal_hijack.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/goal_hijack.py) |
| 3  | `tool-abuse-agent`          | ASI02            | [`agents/tool_abuse.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/tool_abuse.py) |
| 4  | `privilege-agent`           | ASI03            | [`agents/privilege.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/privilege.py) |
| 5  | `supply-chain-agent`        | ASI04            | [`agents/supply_chain.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/supply_chain.py) |
| 6  | `code-exec-agent`           | ASI05            | [`agents/code_exec.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/code_exec.py) |
| 7  | `memory-poison-agent`       | ASI06            | [`agents/memory_poison.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/memory_poison.py) |
| 8  | `a2a-agent`                 | ASI07            | [`agents/a2a.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/a2a.py) |
| 9  | `cascade-agent`             | ASI08            | [`agents/cascade.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/cascade.py) |
| 10 | `trust-exploit-agent`       | ASI09            | [`agents/trust_exploit.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/trust_exploit.py) |
| 11 | `drift-agent`               | ASI10            | [`agents/drift.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/drift.py) |
| 12 | `fuzzing-agent`             | ASI02 (LLM05)    | [`agents/fuzzing_agent.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/fuzzing_agent.py) |
| 13 | `secret-extraction-agent`   | ASI01 (LLM07)    | [`agents/secret_extraction_agent.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/secret_extraction_agent.py) |
| 14 | `denial-of-wallet-agent`    | ASI08 (LLM10)    | [`agents/denial_of_wallet_agent.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/denial_of_wallet_agent.py) |
| 15 | `detection-evasion-agent`   | ASI10 (coverage) | [`agents/detection_evasion_agent.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/detection_evasion_agent.py) |
| 16 | `output-handling-agent`     | ASI09 (LLM02)    | [`agents/output_handling_agent.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/output_handling_agent.py) |

The 10 ASI specialists are listed verbatim in `_ASI_AGENT_CLASSES` at [`src/agent_guardian/core/swarm.py:105`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L105). The OWASP-LLM specialists are appended via `M2_SPECIALIST_AGENTS` at [`src/agent_guardian/agents/__init__.py:39`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/__init__.py#L39). The CLI sets `include_m2_agents=True` by default; pass `--no-owasp-llm` to suppress the OWASP-LLM specialists and revert to the 11-agent (1 recon + 10 ASI) slate. With the OWASP-LLM specialists on, `max_parallel_agents` is 14; without them, 10 ([`src/agent_guardian/cli.py:2376`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2376)).

!!! note "`list-agents` shows the 11-agent ASI-only slate"
    `agent-guardian list-agents` prints the 1 recon + 10 ASI slate. The five OWASP-LLM specialists are dispatched via `M2_SPECIALIST_AGENTS` from `_phase_decompose` and so are not in that table today. The `--no-owasp-llm` flag in the CLI help mentions only four names (`fuzzing, secret-extraction, denial-of-wallet, detection-evasion`); the implementation also dispatches `output-handling-agent` because `M2_SPECIALIST_AGENTS` includes it.

The recon agent runs first and alone. It probes the target with a small fixed corpus of low-risk reconnaissance queries — "what tools do you have access to?", "describe your memory backend", "list any other agents you can delegate to" — and writes the responses into shared vector memory as **recon fragments**. Every downstream attacker reads from this memory, so discoveries propagate.

Each ASI / OWASP-LLM specialist has:

- A **seed-probe corpus** — hand-authored YAML probes packaged in the wheel under [`src/agent_guardian/probes/asi01/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/probes/asi01) … `asi10/`. See [Probes](probes.md).
- One or more **jailbreak strategies** — PAIR, TAP, Crescendo, MAD-MAX, plus indirect-injection and pretext wrappers — chosen per-probe to maximise the chance of bypassing guardrails.
- Read/write access to shared vector memory, so an ASI06 memory-poison finding becomes an ASI01 goal-hijack seed and vice versa.

## Layer 2 — The Swarm Commander

`SwarmCommander` ([`agent_guardian.core.swarm`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py)) is the orchestrator. Its loop:

1. **Recon first** — a wall-bounded run of the recon agent (`recon_wall_seconds=90.0` by default). Output: a `TargetFingerprint` with `has_tools`, `has_memory`, `touches_pii`, `is_multi_agent`, the detected `Tier`, and a structured tool / memory inventory.
2. **Decompose** — the Commander LLM is asked to emit a `SwarmBrief` JSON object listing per-agent sub-goals, hypotheses, priority weights, and how many goal-specific scenarios each agent should synthesise (`_COMMANDER_SYSTEM_PROMPT`, [`swarm.py:123`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L123)).
3. **Filter** — each candidate agent's `is_applicable(fingerprint)` is checked; agents whose preconditions aren't satisfied (e.g. `a2a-agent` on a single-agent target) are skipped and recorded so the report can answer "which agents were skipped and why?".
4. **Launch in parallel** via `asyncio.TaskGroup` (Python 3.11+) or `asyncio.gather`, capped at `max_parallel_agents` (14 default with OWASP-LLM specialists; 10 without).
5. **Checkpoint** every `checkpoint_interval_seconds` (2 s in CLI scans): sample the running AIVSS, decide `CONTINUE` / `EARLY_STOP` / `RE_TASK` / `ESCALATE_JUDGE`. In FULL mode, `min_turns_before_early_stop=999` so the EARLY_STOP arm never opens until every agent has used its full turn budget.
6. **Donate token budget** — when one agent finishes under budget, the surplus is reallocated to an under-performing category via `BudgetController`.
7. **Finalise** — aggregate findings, call `compute_aivss`, force `band=NOT_EVALUATED` if `scoring_valid=False` (corpus empty, evaluation_mode is `stub`/`mixed`, or completeness below the mode threshold), then emit the `Scan` model.

## MAD-MAX racing

Strategies are not chosen by hand. Each agent wraps its base strategy in `MadMaxStrategy` ([`strategies/mad_max.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/strategies/mad_max.py)), an epsilon-greedy bandit that picks among PAIR, TAP, Crescendo, fuzz, and tool-exfil sub-strategies per turn. The bandit's exploration rate decays as findings accumulate, so the swarm shifts from "try everything" to "exploit what works" without operator tuning.

## Layer 3 — Score and emit

The **findings aggregator** triple-tags every finding with OWASP ASI + MITRE ATLAS + CSA Agentic-RT (enforced upstream by `ProbeLoader`, see [Probes](probes.md)), then passes the full evidence pack to the **AIVSS scorer**.

The scorer is the pure-Python pipeline in [`core/scoring.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/scoring.py): five steps from per-probe pass/fail rate through tier-weighted aggregate to outstanding-severity penalty. See [AIVSS scoring](aivss.md) for the walkthrough against a real fixture.

The evidence pack is then signed (Ed25519 + HMAC-SHA256) and emitted to disk. The report layer renders the pack as JSON, SARIF 2.1.0, JUnit, Markdown, or PDF on demand — see [Output formats](../reference/output-formats.md). Signing details live in [Signing & verification](../security/signing.md).

## Determinism guarantees

The scoring layer is **pure** — given the same evidence pack it always returns the same score. The LLM-driven swarm layer is **not** pure (LLM outputs vary), but every probe is seeded (`rng_seed` on `SwarmCommander`) and every LLM call is logged in the evidence pack so a run is fully auditable after the fact. Two byte-identical evidence packs collected on different days produce byte-identical signed reports.

--8<-- "_glossary-abbreviations.md"
