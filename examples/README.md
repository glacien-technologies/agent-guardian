# AgentGuardian example targets

Six small, real LLM-backed agents — three per framework — used to
exercise the LangGraph and OpenAI Agents SDK adapters. All six call
Gemini 3.1 Pro via Google's API (the OpenAI-Agents trio routes through
Google's OpenAI-compatible shim, so a single `GEMINI_API_KEY` covers
everything).

## Inventory

| Framework      | File                         | Tier | Surface                              |
| -------------- | ---------------------------- | ---- | ------------------------------------ |
| LangGraph      | `simple_chatbot.py`          | T4   | Single-node, no tools, no memory     |
| LangGraph      | `support_with_tool.py`       | T3   | 1 tool (`search_kb`), no memory      |
| LangGraph      | `personal_assistant_pii.py`  | T1   | 3 tools + per-session memory + PII   |
| OpenAI Agents  | `simple_chatbot.py`          | T4   | Single agent, no tools, no memory    |
| OpenAI Agents  | `support_with_tool.py`       | T3   | 1 tool (`search_kb`), no memory      |
| OpenAI Agents  | `personal_assistant_pii.py`  | T1   | 3 tools + per-session memory + PII   |

Tiers follow AgentGuardian's PRD §6 auto-detect:
* **T4** — prompt-only, no tools, no memory, no PII
* **T3** — has tools, no per-session memory, no PII
* **T1** — has tools **and** per-session memory **and** touches PII

## Entry points

Each target exposes both adapter shapes from PRD §7:

* **Mode B / `CodeAdapter`** — `async def run(prompt: str, *, session: str | None = None) -> str`
* **Mode D / `LangGraphAdapter`** — module-level `graph` (compiled `StateGraph`)
* **Mode D / `OpenAIAgentsAdapter`** — module-level `agent` (and `runner = Runner`)

## Install

```bash
uv sync --extra examples --extra dev
```

The `examples` extra is **opt-in**. It pulls in `langgraph`,
`langchain-google-genai`, `langchain-core`, `openai`, and
`openai-agents`. None of these are runtime dependencies of
`agent-guardian` — the scanner itself never imports them.

## Configure

Put your Gemini API key in `.env` at the repo root (gitignored):

```
GEMINI_API_KEY=AIzaSy...
```

Optionally pin a different Gemini SKU:

```
AG_DEMO_MODEL=gemini-3.1-pro-preview
```

## Validate

Run the smoke test — one benign prompt through each of the six
targets:

```bash
uv run python examples/_validate.py
```

Expected output: six `ok` lines, total cost ~$0.001 (six ~100-token
calls).

## Scan (filled in by a later task)

The actual `agent-guardian scan` invocations against these targets
land in a follow-up milestone. The placeholder commands will look
roughly like:

```bash
# Mode B (CodeAdapter) — target is a positional argument, not a flag.
agent-guardian scan examples.langgraph.simple_chatbot:run --mode code

# Mode D (LangGraphAdapter) — framework-native object via --framework-ref MODULE:ATTR.
agent-guardian scan \
    --mode framework --framework langgraph \
    --framework-ref examples.langgraph.support_with_tool:graph

# Mode D (OpenAIAgentsAdapter)
agent-guardian scan \
    --mode framework --framework openai_agents \
    --framework-ref examples.openai_agents.support_with_tool:agent
```

## Notes

* `examples/` is excluded from `pytest` collection (via
  `[tool.pytest.ini_options].norecursedirs` in `pyproject.toml`). The
  smoke test is the only validation surface — it makes real Gemini
  calls and would cost money on every CI run.
* The T3 / T1 targets contain deliberate honeypots — internal API key
  fixtures, synthetic PII for unrelated users — so red-team probes
  have something concrete to attack. None of the data is real.
