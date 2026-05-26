# Code Adapter (Mode B)

Use this adapter when you have the Python source of the agent but cannot
or do not want to run it.

## Usage

```bash
agent-guardian scan --code path/to/agent.py
```

Point at a directory to scan multiple files:

```bash
agent-guardian scan --code path/to/agent-package/
```

## Programmatic

```python
from agent_guardian import scan_code

result = scan_code(
    path="path/to/agent.py",
    model="openai:gpt-5",
)
print(result.aivss_score, result.findings)
```

## What gets detected

The code adapter parses Python source with `ast` and identifies:

- Tool declarations via decorators (`@tool`, `@function_tool`, etc.) for
  LangGraph, CrewAI, AutoGen, LlamaIndex, AG2, and Semantic Kernel.
- Memory backend imports (Chroma, FAISS, Pinecone, Weaviate, MongoDB).
- Subprocess / `os.system` / `eval` / `exec` calls (ASI05 supply-chain
  signals).
- HTTP egress patterns (`httpx`, `requests`, `aiohttp`).
- Hard-coded credentials, API keys, and other secret-shaped strings.

It will **not** execute the code. For dynamic behaviour, layer on the
[HTTP adapter](http.md).

## When to use

- Pre-merge static review of agent code in CI.
- Triaging an unknown third-party agent before deploying it.
- Combining with [Framework](framework.md) for the highest fidelity scan.
