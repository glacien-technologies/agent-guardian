# Target Adapters

> **TL;DR.** AgentGuardian accepts your target through one of four
> adapters — System Prompt, Code, HTTP, Framework. All four ship
> **Stable** in v1.0. Pick the highest-fidelity mode your access
> level allows: Framework > HTTP > Code > System Prompt. A handful of
> common integrations (LangChain, MCP server, Claude Agent SDK,
> PydanticAI) are not yet shipped as native adapters — workarounds
> below.

## The four modes

Each adapter normalises its input into a **Target Profile** — the
schema the recon agent consumes. All four produce the same downstream
evidence-pack format, so you can mix-and-match across scans of the
same target as your access level grows.

| Mode | Adapter                                  | Use when                                                            | Status   |
|------|------------------------------------------|---------------------------------------------------------------------|----------|
|  A   | [System prompt](../../how-to/scan-a-system-prompt.md)| You only have the agent's system prompt                             | Stable   |
|  B   | [Code](../../how-to/scan-python-source.md)           | You have the Python source of the agent                             | Stable   |
|  C   | [HTTP](../../how-to/scan-an-http-endpoint.md)           | The agent is reachable as an HTTP endpoint                          | Stable   |
|  D   | [Framework](framework.md)                | LangGraph / CrewAI / AutoGen / OpenAI Agents SDK / Strands / ADK    | Stable   |

The four CLI flags (`--system-prompt`, positional `TARGET`,
`--endpoint`, `--framework`) are mutually exclusive — `scan` exits
with `EXIT_CONFIG` (code `2`) if you pass more than one or none
(`src/agent_guardian/cli.py:457-467`).

## Which mode for my agent?

```text
Do you have the framework-native runtime object
(compiled LangGraph, CrewAI Crew, AutoGen GroupChat,
OpenAI Agents Agent, Strands Agent, ADK Runner)?
         │
         ├── yes ──► Mode D (Framework) — highest fidelity, sees the
         │          real tool graph, memory backends, inter-agent edges.
         │          See: framework.md
         │
         └── no
             │
             Is the agent reachable as an HTTP endpoint?
                 │
                 ├── yes ──► Mode C (HTTP) — second-best.
                 │          See: ../../how-to/scan-an-http-endpoint.md
                 │
                 └── no
                     │
                     Do you have the Python source / a callable?
                         │
                         ├── yes ──► Mode B (Code).
                         │          See: ../../how-to/scan-python-source.md
                         │
                         └── no ──► Mode A (System Prompt).
                                    See: ../../how-to/scan-a-system-prompt.md
```

**Framework** is the highest fidelity because the framework adapter
introspects the framework's runtime objects directly. **HTTP** is
next-best when you only have a deployed endpoint. **Code** parses the
source. **System prompt** is the lowest-fidelity mode — it gives the
recon agent only what the agent itself would say it can do.

## Not yet supported as a framework adapter

The following are commonly requested but **not** shipped as native
framework adapters in v1.0. Each row lists the realistic workaround
today plus the roadmap target.

| Framework                              | Status today                                        | Workaround                                                                                                                                            | Tracked under                          |
|----------------------------------------|-----------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------|
| **LangChain** (non-LangGraph)          | Not a v1.0 adapter.                                 | Use [LangGraph](framework.md) (LangChain's runtime successor) or wrap your chain in a Python callable for [Mode B Code](../../how-to/scan-python-source.md).      | [Roadmap](../../reference/roadmap.md) v1.1+      |
| **MCP server**                         | Not a v1.0 adapter; transport client exists.        | Scan the MCP server's HTTP surface via [Mode C HTTP](../../how-to/scan-an-http-endpoint.md).                                                                          | [Roadmap](../../reference/roadmap.md) v1.1       |
| **Azure OpenAI**                       | Not a "framework" — it's an OpenAI-compatible LLM.  | Point `OpenAIClient(base_url=...)` at your Azure deployment (see [providers/openai.md](../providers/openai.md#custom-base-url-azure-openai-gateways-mocks)). For the Foundry thread/run data plane use [`AzureFoundryAgentTransport`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/transports/azure_foundry.py). | n/a — already covered via providers / transports |
| **Anthropic Claude Agent SDK**         | Not a v1.0 adapter.                                 | Wrap your agent's entry function in a Python callable for [Mode B Code](../../how-to/scan-python-source.md).                                                       | [Roadmap](../../reference/roadmap.md) v1.1       |
| **PydanticAI**                         | Not a v1.0 adapter.                                 | Wrap your agent's `run`/`run_sync` in a callable for [Mode B Code](../../how-to/scan-python-source.md).                                                            | [Roadmap](../../reference/roadmap.md) v1.1       |
| **LlamaIndex / AG2 / Semantic Kernel** | Not a v1.0 adapter.                                 | Same workaround — wrap as a Python callable or expose via HTTP.                                                                                       | [Roadmap](../../reference/roadmap.md) v1.2       |

If none of the modes above describes your target, file an issue at
<https://github.com/glacien-technologies/agent-guardian/issues> with
the framework name and a minimal `run(prompt) -> str` shape — that's
all an adapter needs to ship.
