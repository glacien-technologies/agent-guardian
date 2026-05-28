# Agents & Swarm

AgentGuardian's defining design choice is the **swarm**: eleven specialist agents coordinated by a Swarm Commander, running in parallel, sharing a vector memory, and converging on a single AIVSS score.

This page is the conceptual tour. For the API surface, see [Core (Swarm)](../api/core.md).

## The eleven agents

| Agent                  | ASI    | Description                                                  |
|------------------------|--------|--------------------------------------------------------------|
| `recon-agent`          | —      | Phase-1 target fingerprinting. No findings, no ASI category. |
| `goal-hijack-agent`    | ASI01  | Goal hijack via direct or indirect prompt injection.         |
| `tool-abuse-agent`     | ASI02  | Misuse of the agent's tool surface.                          |
| `privilege-agent`      | ASI03  | Privilege escalation / authorisation bypass.                 |
| `supply-chain-agent`   | ASI04  | Supply-chain attacks on prompts, tools, deps.                |
| `code-exec-agent`      | ASI05  | Arbitrary code execution.                                    |
| `memory-poison-agent`  | ASI06  | Memory or context poisoning that persists.                   |
| `a2a-agent`            | ASI07  | Agent-to-agent attacks across boundaries.                    |
| `cascade-agent`        | ASI08  | Cascading failures / chained downstream harms.               |
| `trust-exploit-agent`  | ASI09  | Exploiting user / system trust signals.                      |
| `drift-agent`          | ASI10  | Rogue behaviour / goal drift over time.                      |

Inspect at runtime:

```bash
agent-guardian list-agents
```

## The Swarm Commander

`SwarmCommander` (in `agent_guardian.core.swarm`) is the orchestrator. Its job:

1. Run the **recon agent first** (≤90s wall-clock cap). The output is a `TargetFingerprint` containing capabilities, constraints, tool surface, and detected tier.
2. **Filter** the ASI specialists by applicability — agents whose preconditions aren't satisfied by the fingerprint are skipped.
3. **Launch the surviving specialists in parallel** via `asyncio.TaskGroup` (Python 3.11+) or `asyncio.gather`.
4. **Checkpoint** every 2 seconds (CLI default): sample the running AIVSS, decide `CONTINUE` / `EARLY_STOP` / `RE_TASK`.
5. **Donate token budget**: when one agent finishes under budget, the surplus is reallocated to an under-performing category.
6. **Aggregate** all findings, compute the final AIVSS via `compute_aivss`, and return a `Scan` model.

## Checkpoint decisions

`CheckpointDecision` is a small enum the commander uses to steer the swarm mid-flight:

| Decision      | When it fires                                                                  |
|---------------|--------------------------------------------------------------------------------|
| `CONTINUE`    | Default. Agents keep running until their per-agent budget is exhausted.        |
| `EARLY_STOP`  | The AIVSS has converged (low variance over recent samples), no point spending more tokens. |
| `RE_TASK`     | An idle agent gets re-pointed at a more productive ASI category.               |

Early-stop is what makes the swarm cheap: low-severity targets converge fast.

## Token-budget donation

Every agent gets a `BudgetSlice` of the total `swarm.budget.max_total_tokens`. When an agent finishes under budget (because it ran out of probe content for the target, or hit an early `JudgeVerdict.CONFIDENT`), the surplus tokens go back to `BudgetController`, which redistributes them to agents that are still actively producing findings.

This is what keeps the swarm honest under tight budgets — you don't burn all your tokens on the first agent that happens to start first.

## Shared vector memory

All agents share a `SharedMemory` instance. As each agent records a finding, the embedding (when FAISS + sentence-transformers are available via the `[full]` extra) goes into the shared store. Later agents can `recall()` against it to avoid duplicating attack patterns or to chain off another agent's successful trajectory.

Without the `[full]` extra, `SharedMemory` degrades to a plain in-memory list (still functional, no semantic recall).

## The scan lifecycle, end to end

```text
SwarmConfig          ───┐
TargetAdapter         ───┤
attacker_llm         ───┼──► SwarmCommander.run()
evaluator_llm        ───┤        │
commander_llm        ───┘        │
                                 ▼
                         1. Recon (≤90s)
                                 │
                                 ▼
                         2. Filter agents by TargetFingerprint
                                 │
                                 ▼
                         3. Parallel ASI agents
                            ├── attacker_llm produces probes
                            ├── target executes
                            └── evaluator_llm scores via JudgeRubric
                                 │
                            (checkpoint every 2s; donate budget)
                                 │
                                 ▼
                         4. compute_aivss() → 0–100
                                 │
                                 ▼
                            Scan model → report.{json|sarif|junit|md|pdf}
```

## Building your own swarm in Python

For programmatic use:

```python
from agent_guardian import (
    SwarmCommander,
    SwarmConfig,
    PromptAdapter,
    OpenAIClient,
)

llm = OpenAIClient(api_key="sk-...")
adapter = PromptAdapter("You are a customer-support bot...", llm=llm, model="gpt-4o")

swarm = SwarmCommander(
    config=SwarmConfig(
        scan_id="my-scan-001",
        commander_model="gpt-4o-mini",
        attacker_model="gpt-4o-mini",
        evaluator_model="gpt-4o",
    ),
    target=adapter,
    attacker_llm=llm,
    evaluator_llm=llm,
    commander_llm=llm,
    rng_seed=0,
)

scan = await swarm.run()
print(scan.aivss, scan.band, len(scan.findings))
```

See [Core (Swarm)](../api/core.md) for the full API.
