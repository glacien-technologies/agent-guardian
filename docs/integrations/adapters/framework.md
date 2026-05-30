# Framework Adapter (Mode D)

> **TL;DR.** Six framework adapters ship in v1.0 — LangGraph, OpenAI
> Agents SDK, CrewAI, AutoGen, Strands, and Google ADK. Wire them
> from the CLI via `--framework KIND --framework-ref MODULE:ATTR`, or
> from Python by passing the framework-native runtime object into the
> matching adapter class. This is the highest-fidelity mode because
> the adapter introspects the framework's runtime objects directly.

## Supported frameworks

The OSS v1.0 wheel ships six framework adapters. They are concrete
subclasses of `FrameworkAdapter`, exported from the top-level package
(`src/agent_guardian/adapters/framework/__init__.py`).

| Framework         | Class                | Constructor arg                                | CLI `--framework` token | Status | Demo target                                       |
|-------------------|----------------------|------------------------------------------------|-------------------------|--------|---------------------------------------------------|
| LangGraph         | `LangGraphAdapter`   | a compiled `StateGraph` (`graph`)              | `langgraph`             | Stable | [`examples/langgraph/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/simple_chatbot.py) |
| OpenAI Agents SDK | `OpenAIAgentsAdapter`| an `Agent` (+ optional `runner=`)              | `openai_agents`         | Stable | [`examples/openai_agents/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/simple_chatbot.py) |
| CrewAI            | `CrewAIAdapter`      | a `Crew` instance (`crew`)                     | `crewai`                | Stable | Demo target on the [Roadmap](../../reference/roadmap.md).   |
| AutoGen           | `AutoGenAdapter`     | a `GroupChat` instance (`group_chat`)          | `autogen`               | Stable | Demo target on the [Roadmap](../../reference/roadmap.md).   |
| Strands           | `StrandsAdapter`     | a Strands `Agent` (`agent`)                    | `strands`               | Stable | Demo target on the [Roadmap](../../reference/roadmap.md).   |
| Google ADK        | `ADKAdapter`         | an ADK `Runner` (`runner`)                     | `adk`                   | Stable | Demo target on the [Roadmap](../../reference/roadmap.md).   |

Each adapter duck-types the framework — AgentGuardian does **not**
import LangGraph / CrewAI / AutoGen / Strands / ADK as runtime
dependencies, so the adapters work with whatever pinned version your
project uses.

## Not yet shipped

The following are on the roadmap but **not** in v1.0. See
[Roadmap](../../reference/roadmap.md) for target versions; see
[Adapters overview — Not yet supported](index.md#not-yet-supported-as-a-framework-adapter)
for the workaround in the meantime.

| Framework                          | Target version          |
|------------------------------------|-------------------------|
| LangChain (non-LangGraph)          | v1.1+                   |
| MCP server                         | v1.1                    |
| Anthropic Claude Agent SDK         | v1.1                    |
| PydanticAI                         | v1.1                    |
| LlamaIndex                         | v1.2                    |
| AG2                                | v1.2                    |
| Semantic Kernel                    | v1.2                    |

## From the CLI

The CLI dispatches frameworks via two flags:

- `--framework KIND` — one of `adk`, `autogen`, `crewai`,
  `langgraph`, `openai_agents`, `strands`
  (`src/agent_guardian/cli.py:104-111`).
- `--framework-ref MODULE:ATTR` — a Python dotted reference to the
  framework-native object (`src/agent_guardian/cli.py:114-158`). The
  colon form (`my_app.graph:graph`) is preferred; the dotted form
  (`my_app.graph.graph`) is accepted for ergonomics.

The CLI imports the module, pulls the attribute, then constructs the
adapter with it (`src/agent_guardian/cli.py:482-506`).

### LangGraph — runnable example

The repo ships a working LangGraph demo target. From the repo root:

```bash
export GEMINI_API_KEY=...   # the demo target routes inference via Gemini

agent-guardian scan \
  --framework langgraph \
  --framework-ref examples.langgraph.simple_chatbot:graph \
  --mode quick \
  --model openai:gpt-4o-mini
```

`examples.langgraph.simple_chatbot:graph` resolves to the module-level
compiled `StateGraph` at
[`examples/langgraph/simple_chatbot.py:58`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/simple_chatbot.py).

### OpenAI Agents SDK — runnable example

```bash
export GEMINI_API_KEY=...   # the demo target routes inference via Gemini

agent-guardian scan \
  --framework openai_agents \
  --framework-ref examples.openai_agents.simple_chatbot:agent \
  --mode quick \
  --model openai:gpt-4o-mini
```

`examples.openai_agents.simple_chatbot:agent` resolves to the
module-level `Agent` at
[`examples/openai_agents/simple_chatbot.py:37`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/simple_chatbot.py).

### CrewAI / AutoGen / Strands / ADK — same shape

Substitute the `--framework` token and the `MODULE:ATTR` for your own
crew / group-chat / agent / runner:

```bash
# CrewAI
agent-guardian scan \
  --framework crewai \
  --framework-ref my_app.crew:crew \
  --model openai:gpt-4o-mini

# AutoGen
agent-guardian scan \
  --framework autogen \
  --framework-ref my_app.team:group_chat \
  --model openai:gpt-4o-mini

# Strands
agent-guardian scan \
  --framework strands \
  --framework-ref my_app.agent:agent \
  --model openai:gpt-4o-mini

# Google ADK
agent-guardian scan \
  --framework adk \
  --framework-ref my_app.runner:runner \
  --model openai:gpt-4o-mini
```

### CLI errors you may see

- *unknown `--framework` …* — the kind wasn't one of the six
  supported tokens (`cli.py:486-490`).
- *`--framework-ref` is empty / not in MODULE:ATTR …* — the ref didn't
  parse (`cli.py:126-141`).
- *could not import module …* — the module on the ref couldn't be
  imported in the CLI process (`cli.py:143-148`).
- *attribute path … not found* — the module imported but the attribute
  walk failed (`cli.py:149-157`).
- *adapter rejected the object from …* — the adapter's `__init__`
  raised because the native object didn't quack right (`cli.py:501-506`;
  e.g. `LangGraphAdapter` requires a graph with `.ainvoke()` or
  `.invoke()` — `src/agent_guardian/adapters/framework/langgraph.py:36-40`).

## From Python

The CLI is a thin wrapper. Anything `--framework` does is reachable
from Python — pass the native runtime object into the matching adapter
class.

### LangGraph

```python
import asyncio

from agent_guardian import (
    LangGraphAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)
from examples.langgraph.simple_chatbot import graph  # compiled StateGraph


async def main() -> None:
    adapter = LangGraphAdapter(graph)
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

### OpenAI Agents SDK

```python
from agent_guardian import OpenAIAgentsAdapter
from examples.openai_agents.simple_chatbot import agent  # openai-agents Agent

adapter = OpenAIAgentsAdapter(agent)
# Or, if your agent doesn't expose .run() / .run_async() itself:
# adapter = OpenAIAgentsAdapter(agent, runner=Runner)
```

The `runner=` kwarg is the SDK's canonical pattern when the agent
itself isn't callable — see
[`src/agent_guardian/adapters/framework/openai_agents.py:34-66`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/openai_agents.py).

### CrewAI, AutoGen, Strands, ADK

The pattern is the same — pass the top-level runtime object (a
`Crew`, a `GroupChat`, a Strands `Agent`, or an ADK `Runner`) into the
matching adapter class:

```python
from agent_guardian import (
    ADKAdapter,
    AutoGenAdapter,
    CrewAIAdapter,
    StrandsAdapter,
)

crewai_adapter  = CrewAIAdapter(my_crew)
autogen_adapter = AutoGenAdapter(my_group_chat)
strands_adapter = StrandsAdapter(my_strands_agent)
adk_adapter     = ADKAdapter(my_adk_runner)
```

## Per-framework how-to guides

Each framework has a longer step-by-step how-to with environment setup,
common mistakes, and the full end-to-end recipe:

- [Wire LangGraph](../../how-to/wire-langgraph.md)
- [Wire OpenAI Agents SDK](../../how-to/wire-openai-agents.md)
- [Wire CrewAI](../../how-to/wire-crewai.md)
- [Wire AutoGen](../../how-to/wire-autogen.md)
- [Wire AWS Strands](../../how-to/wire-strands.md)
- [Wire Google ADK](../../how-to/wire-adk.md)

## What gets detected

Mode D sees everything the Code adapter sees, plus:

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
