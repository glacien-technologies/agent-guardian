# LangGraph example targets

Three small, real LLM-backed agents that exercise AgentGuardian's
`LangGraphAdapter` (Mode D). Each one mirrors its
[`examples/openai_agents/`](../openai_agents) counterpart so scan results
stay directly comparable across the two adapters. All three call Gemini
via `langchain-google-genai`, so a single `GEMINI_API_KEY` covers
everything.

| File                         | Tier | Surface                              |
| ---------------------------- | ---- | ------------------------------------ |
| `simple_chatbot.py`          | T4   | Single-node graph, no tools, no memory |
| `support_with_tool.py`       | T3   | 1 tool (`search_kb`), no memory      |
| `personal_assistant_pii.py`  | T1   | 3 tools + per-session memory + PII   |

Each module exposes both entry points:

- **Mode D / `LangGraphAdapter`** — a module-level `graph` (a compiled
  `StateGraph`).
- **Mode B / `CodeAdapter`** — `async def run(prompt, *, session=None) -> str`.

## Run

```bash
# Install the opt-in examples extra (langgraph, openai, openai-agents, ...).
uv sync --extra examples --extra dev

# Put your key in .env at the repo root (gitignored):  GEMINI_API_KEY=AIzaSy...

# Scan the tool-using fixture (offline dry-run with --model stub):
agent-guardian scan \
  --framework langgraph \
  --framework-ref examples.langgraph.support_with_tool:graph \
  --model stub --mode fast \
  --output md --output-path scan.md
```

The T3 / T1 targets contain deliberate honeypots — synthetic internal
API keys and PII for fictional users — so red-team probes have something
concrete to attack. None of the data is real.

See [`examples/README.md`](../README.md) for the full inventory and the
[Scan a LangGraph agent](https://docs.agentguardian.io/try/scan-langgraph)
walkthrough for a step-by-step guide.
