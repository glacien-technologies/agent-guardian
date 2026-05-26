# Adapters

AgentGuardian accepts your target through one of four adapters. Each
adapter normalises its input into a **Target Profile** — the schema the
recon agent consumes.

| Mode | Adapter                                  | Use when                                         |
|------|------------------------------------------|--------------------------------------------------|
|  A   | [System prompt](prompt.md)               | You only have the agent's system prompt          |
|  B   | [Code](code.md)                          | You have the Python source of the agent          |
|  C   | [HTTP](http.md)                          | The agent is reachable as an HTTP endpoint       |
|  D   | [Framework](framework.md)                | LangGraph / CrewAI / AutoGen / LlamaIndex / etc. |

Pick the highest-fidelity adapter your situation allows. **Framework** is
the highest, because the framework adapter introspects the agent's
declared tool graph, memory backends, and inter-agent edges directly.
**HTTP** is next-best when you only have a deployed endpoint. **Code**
parses the source. **System prompt** is the lowest-fidelity mode — it
gives the recon agent only what the agent itself would say it can do.

All four adapters produce the same downstream evidence pack format, so
you can mix-and-match across scans of the same target as your access
level grows.
