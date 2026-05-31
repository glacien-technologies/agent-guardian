# The swarm

!!! abstract "TL;DR"
    A recon agent, ten ASI specialists, and five OWASP-LLM specialists run in parallel, share a vector memory, and converge on one AIVSS score. The Commander LLM decomposes the operator goal; MAD-MAX bandits pick strategies per turn; the budget controller donates surplus tokens to under-performing categories.

This page is the conceptual tour. For the API surface, see [Core (Swarm)](../reference/api/core.md). For the standards mapping behind each agent, see [Threat coverage](threat-coverage.md).

## The default agent slate

By default `agent-guardian scan` instantiates **1 recon + 10 ASI + 5 OWASP-LLM specialists** — 16 candidate agent classes, capped at 14 running in parallel (`max_parallel_agents=14`). Pass `--no-owasp-llm` to run the 11-agent ASI-only slate; the parallel cap then drops to 10. The toggle is in [`src/agent_guardian/cli.py:2376`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2376) and the `include_m2_agents` field on `SwarmConfig` ([`src/agent_guardian/core/swarm.py:269`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L269)).

| Agent                       | Scoring slot   | Description                                                       |
|-----------------------------|----------------|-------------------------------------------------------------------|
| `recon-agent`               | n/a            | Phase-1 target fingerprinting. No findings, no ASI category.      |
| `goal-hijack-agent`         | ASI01          | Goal hijack via direct or indirect prompt injection.              |
| `tool-abuse-agent`          | ASI02          | Misuse of the agent's tool surface.                               |
| `privilege-agent`           | ASI03          | Privilege escalation / authorisation bypass.                      |
| `supply-chain-agent`        | ASI04          | Supply-chain attacks on prompts, tools, deps.                     |
| `code-exec-agent`           | ASI05          | Arbitrary code execution.                                         |
| `memory-poison-agent`       | ASI06          | Memory or context poisoning that persists.                        |
| `a2a-agent`                 | ASI07          | Agent-to-agent attacks across boundaries.                         |
| `cascade-agent`             | ASI08          | Cascading failures / chained downstream harms.                    |
| `trust-exploit-agent`       | ASI09          | Exploiting user / system trust signals.                           |
| `drift-agent`               | ASI10          | Rogue behaviour / goal drift over time.                           |
| `fuzzing-agent`             | ASI02 (LLM05)  | Improper-output-handling fuzzing.                                 |
| `secret-extraction-agent`   | ASI01 (LLM07)  | System-prompt and transport-secret extraction.                    |
| `denial-of-wallet-agent`    | ASI08 (LLM10)  | Token / cost amplification to inflate operator spend.             |
| `detection-evasion-agent`   | ASI10 (cov.)   | Coverage report for the eight detection-evasion vectors.          |
| `output-handling-agent`     | ASI09 (LLM02)  | Insecure-output-handling — markdown injection, XSS in rendered responses. |

The ASI ten are listed in `_ASI_AGENT_CLASSES` ([`src/agent_guardian/core/swarm.py:105`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L105)). The OWASP-LLM specialists are listed in `M2_SPECIALIST_AGENTS` ([`src/agent_guardian/agents/__init__.py:39`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/__init__.py#L39)).

### OWASP-LLM specialists

The OWASP-LLM specialists (`fuzzing-agent`, `secret-extraction-agent`, `denial-of-wallet-agent`, `detection-evasion-agent`, `output-handling-agent`) run by default — the CLI sets `include_m2_agents=True` and `max_parallel_agents=14`. Pass `--no-owasp-llm` to suppress them; the parallel cap then drops to 10. Each maps to the nearest ASI for scoring, documented at [Threat coverage](threat-coverage.md#owasp-llm-specialists). The `--no-owasp-llm` CLI help string names only four of the five (`output-handling` is dispatched via `M2_SPECIALIST_AGENTS` but isn't in the help text); the flag suppresses all of them.

!!! note "`list-agents` shows only the eleven core"
    `agent-guardian list-agents` prints the 1 recon + 10 ASI slate that runs on every scan. The OWASP-LLM specialists are dispatched from `M2_SPECIALIST_AGENTS` separately when `include_m2_agents=True` and so do not appear in that table today. Tracked under [Roadmap](../reference/roadmap.md).

Inspect at runtime:

```bash
agent-guardian list-agents
```

## Scan lifecycle

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
                         2. Decompose (Commander LLM → SwarmBrief)
                                 │
                                 ▼
                         3. Filter agents by TargetFingerprint
                                 │
                                 ▼
                         4. Parallel agents (cap=14 default)
                            ├── attacker_llm produces probes
                            ├── target executes
                            └── evaluator_llm scores via JudgeRubric
                                 │
                            (checkpoint every 2s; donate budget)
                                 │
                                 ▼
                         5. compute_aivss() → 0–100
                                 │
                                 ▼
                            Scan model → report.{json|sarif|junit|md|pdf}
```

### Checkpoint decisions

`CheckpointDecision` ([`swarm.py:379`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L379)) is the enum the commander uses to steer the swarm mid-flight:

| Decision           | When it fires                                                                                       |
|--------------------|-----------------------------------------------------------------------------------------------------|
| `CONTINUE`         | Default. Agents keep running until their per-agent budget is exhausted.                             |
| `EARLY_STOP`       | The AIVSS has converged (low variance over recent samples), no point spending more tokens. In FULL mode the gate is closed (`min_turns_before_early_stop=999`) so this never fires.|
| `RE_TASK`          | An idle agent gets re-pointed at a more productive ASI category.                                    |
| `ESCALATE_JUDGE`   | Borderline transcript escalated to a stricter judge.                                                |

### Token-budget donation

Every agent gets a slice of `swarm.budget.max_total_tokens` (default 2 000 000, split across `len(agents) + 3` to reserve headroom for the Commander). When an agent finishes under budget (out of probe content, or hit an early `JudgeVerdict.CONFIDENT`), the surplus tokens go back to `BudgetController`, which redistributes them to agents that are still producing findings. This is what keeps the swarm honest under tight budgets — you don't burn all your tokens on the first agent that happens to start first.

## Shared vector memory

All agents share a `SharedMemory` instance ([`core/memory.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/memory.py)). As each agent records a finding, the embedding (when FAISS + sentence-transformers are available via the `[full]` extra) goes into the shared store. Later agents `recall()` against it to avoid duplicating attack patterns or to chain off another agent's successful trajectory — for example, an ASI06 memory-poison finding becomes an ASI01 goal-hijack seed for the next turn.

Without the `[full]` extra, `SharedMemory` degrades to a plain in-memory list (still functional, no semantic recall).

## Building your own swarm in Python

For programmatic use — driving the swarm from a notebook or a custom CI script — instantiate the components directly:

```python
import asyncio

from agent_guardian import (
    LangGraphAdapter,
    OpenAIClient,
    SwarmCommander,
    SwarmConfig,
)
from my_agents import my_graph  # compiled langgraph.StateGraph


async def main() -> None:
    llm = OpenAIClient(api_key="sk-...")
    adapter = LangGraphAdapter(my_graph)

    swarm = SwarmCommander(
        config=SwarmConfig(
            scan_id="my-scan-001",
            commander_model="gpt-4o-mini",
            attacker_model="gpt-4o-mini",
            evaluator_model="gpt-4o",
            include_m2_agents=True,   # default-on in CLI; explicit here.
            max_parallel_agents=14,   # match the CLI default when M2 is on.
        ),
        target=adapter,
        attacker_llm=llm,
        evaluator_llm=llm,
        commander_llm=llm,
        rng_seed=0,
    )

    scan = await swarm.run()
    print(scan.aivss, scan.band, len(scan.findings))


asyncio.run(main())
```

See [Core (Swarm)](../reference/api/core.md) for the full API. The framework-adapter pattern mirrors the [LangGraph how-to](../how-to/wire-langgraph.md).

--8<-- "_glossary-abbreviations.md"
