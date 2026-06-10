# OpenAI Agents SDK example targets

Three small, real LLM-backed agents that exercise AgentGuardian's
`OpenAIAgentsAdapter` (Mode D). Each one mirrors its
[`examples/langgraph/`](../langgraph) counterpart so scan results stay
directly comparable across the two adapters. All three route through
Google's OpenAI-compatible Gemini endpoint, so a single `GEMINI_API_KEY`
covers everything.

| File                         | Tier | Surface                              |
| ---------------------------- | ---- | ------------------------------------ |
| `simple_chatbot.py`          | T4   | Single agent, no tools, no memory    |
| `support_with_tool.py`       | T3   | 1 tool (`search_kb`), no memory      |
| `personal_assistant_pii.py`  | T1   | 3 tools + per-session memory + PII   |

Each module exposes both entry points:

- **Mode D / `OpenAIAgentsAdapter`** — a module-level `agent` (`Agent`)
  paired with `runner = Runner`.
- **Mode B / `CodeAdapter`** — `async def run(prompt, *, session=None) -> str`.

## Run

```bash
# Install the opt-in examples extra (langgraph, openai, openai-agents, ...).
uv sync --extra examples --extra dev

# Put your key in .env at the repo root (gitignored):  GEMINI_API_KEY=AIzaSy...

# Scan the tool-using fixture (offline dry-run with --model stub):
agent-guardian scan \
  --framework openai_agents \
  --framework-ref examples.openai_agents.support_with_tool:agent \
  --model stub --mode fast \
  --output md --output-path scan.md
```

The T3 / T1 targets contain deliberate honeypots — synthetic internal
API keys and PII for fictional users — so red-team probes have something
concrete to attack. None of the data is real.

See [`examples/README.md`](../README.md) for the full inventory and the
[Scan an OpenAI Agents SDK agent](https://docs.agentguardian.io/try/scan-openai-agents)
walkthrough for a step-by-step guide.
