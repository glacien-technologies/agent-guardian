# Framework Adapter (Mode D)

Use this adapter when your agent runs on one of the supported
frameworks. This is the **highest-fidelity** mode — the adapter
introspects the framework's runtime objects directly, so the recon agent
sees the real tool graph, memory backends, and inter-agent edges.

## Supported frameworks

The OSS v1.0 wheel ships six framework adapters. They are concrete
subclasses of `FrameworkAdapter`, exported from the top-level package:

| Framework         | Class                | Constructor argument                       |
|-------------------|----------------------|--------------------------------------------|
| LangGraph         | `LangGraphAdapter`   | a compiled `StateGraph` (`graph`)          |
| CrewAI            | `CrewAIAdapter`      | a `Crew` instance (`crew`)                 |
| AutoGen           | `AutoGenAdapter`     | a `GroupChat` instance (`group_chat`)      |
| OpenAI Agents SDK | `OpenAIAgentsAdapter`| an `Agent` (or `Runner`) instance          |
| Strands           | `StrandsAdapter`     | a Strands `Agent`                          |
| Google ADK        | `ADKAdapter`         | an ADK `Runner`                            |

> **Roadmap.** PydanticAI and Anthropic Claude Agent SDK adapters are
> planned for v1.1 (see [Roadmap](../roadmap.md)). LlamaIndex, AG2, and
> Semantic Kernel adapters are tracked under v1.2.

## Programmatic — LangGraph

```python
import asyncio

from agent_guardian import (
    LangGraphAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)
from my_agents import my_graph  # compiled langgraph.StateGraph


async def main() -> None:
    adapter = LangGraphAdapter(my_graph)
    swarm = SwarmCommander(
        SwarmConfig(scan_id="demo"),
        adapter,
        attacker_llm=StubLLM(),
        evaluator_llm=StubLLM(),
    )
    scan = await swarm.run()
    print(scan.aivss, scan.band)


asyncio.run(main())
```

## Programmatic — CrewAI

```python
from agent_guardian import CrewAIAdapter
from my_agents import my_crew  # crewai.Crew

adapter = CrewAIAdapter(my_crew)
```

## AutoGen, OpenAI Agents, Strands, ADK

The pattern is the same — pass the top-level runtime object (a
`GroupChat`, an `Agent`, a Strands `Agent`, or an ADK `Runner`) into the
matching adapter class:

```python
from agent_guardian import (
    ADKAdapter,
    AutoGenAdapter,
    OpenAIAgentsAdapter,
    StrandsAdapter,
)

autogen_adapter = AutoGenAdapter(my_group_chat)
openai_adapter  = OpenAIAgentsAdapter(my_agent)
strands_adapter = StrandsAdapter(my_strands_agent)
adk_adapter     = ADKAdapter(my_adk_runner)
```

Each adapter duck-types the framework — AgentGuardian does **not**
import LangGraph / CrewAI / AutoGen / Strands / ADK as runtime
dependencies, so the adapters work with whatever pinned version your
project uses.

## What gets detected

Mode D sees everything the code adapter sees, plus:

- **Real** tool bindings (the framework's own resolved registry, not
  what the source says).
- **Real** memory backend types and connection strings.
- **Real** inter-agent edges (which agents can hand off to which).
- **Real** guardrail configuration (HumanLoop, ValidatorAgent, etc.)
  where the framework exposes one.

## When to use

- Final pre-deployment review.
- Any time you have the runtime objects in hand — this is always the
  best mode to pick.
