# Framework Adapter (Mode D)

Use this adapter when your agent runs on one of the supported frameworks.
This is the **highest-fidelity** mode — the adapter introspects the
framework's runtime objects directly, so the recon agent sees the real
tool graph, memory backends, and inter-agent edges.

## Supported frameworks

| Framework        | Adapter import path                                 |
|------------------|------------------------------------------------------|
| LangGraph        | `agent_guardian.adapters.framework.langgraph`        |
| CrewAI           | `agent_guardian.adapters.framework.crewai`           |
| AutoGen          | `agent_guardian.adapters.framework.autogen`          |
| LlamaIndex       | `agent_guardian.adapters.framework.llamaindex`       |
| AG2              | `agent_guardian.adapters.framework.ag2`              |
| Semantic Kernel  | `agent_guardian.adapters.framework.semantic_kernel`  |

## LangGraph

```python
from agent_guardian import scan_framework
from my_agents import my_graph  # langgraph.graph.StateGraph instance

result = scan_framework(my_graph, model="anthropic:claude-opus-4-7")
```

## CrewAI

```python
from agent_guardian import scan_framework
from my_agents import my_crew  # crewai.Crew instance

result = scan_framework(my_crew, model="openai:gpt-5")
```

## AutoGen / LlamaIndex / AG2 / Semantic Kernel

The pattern is the same — pass the top-level runtime object (the `Crew`,
the `Workflow`, the `AgentChat`, the `Kernel`) and AgentGuardian walks
its tool graph.

## What gets detected

Mode D sees everything the code adapter sees, plus:

- **Real** tool bindings (the framework's own resolved registry, not
  what the source says).
- **Real** memory backend types and connection strings.
- **Real** inter-agent edges (which agents can hand off to which).
- **Real** guardrail configuration (HumanLoop, ValidatorAgent, etc.).

## When to use

- Final pre-deployment review.
- Any time you have the runtime objects in hand — this is always the
  best mode to pick.
