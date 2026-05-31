# OpenAI Agents - simple chatbot (T4)

**TL;DR.** The same T4 stateless customer-service chatbot as the LangGraph version, wired through the OpenAI Agents SDK. Single `Agent`, no tools, no memory. Use it to verify the `OpenAIAgentsAdapter` end-to-end against the smallest possible target.

## Prerequisites

Same as the [gallery](index.md#prerequisites): clone the repo, run `uv sync --extra examples --extra dev`, put `GEMINI_API_KEY=...` in `.env`. The OpenAI Agents SDK trio routes through Google's OpenAI-compatible Gemini endpoint via `OpenAIChatCompletionsModel`, so the single Gemini key covers both trios.

## Source

Live file: [`examples/openai_agents/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/simple_chatbot.py).

```python
--8<-- "examples/openai_agents/simple_chatbot.py"
```

The two AgentGuardian entry points:

- `agent` (line 37) — the `Agent` instance for `OpenAIAgentsAdapter` (Mode D), paired with `runner = Runner` (line 38). The adapter accepts either pattern.
- `run(prompt, *, session=None)` (line 41) — async callable for `CodeAdapter` (Mode B). `session` is accepted for signature compatibility but unused — T4 is stateless.

## Scan it - Mode B (CodeAdapter)

```bash
agent-guardian scan examples.openai_agents.simple_chatbot:run \
    --model stub --no-tui --mode fast
```

Expected final line:

```
scan cli-<id> done: AIVSS=n/a band=not_evaluated tier=T4 findings=0 report=/Users/<you>/.agentguardian/scans/cli-<id>/report.json
```

The `band=not_evaluated` is correct under `--model stub` — see the explanation on the [LangGraph T4 page](langgraph-simple-chatbot.md#scan-it-mode-b-codeadapter). For an authoritative score, swap in a real provider — see [LLM providers](../integrations/providers/index.md).

## Scan it - Mode D (OpenAIAgentsAdapter)

```bash
agent-guardian scan \
    --framework openai_agents \
    --framework-ref examples.openai_agents.simple_chatbot:agent \
    --model stub --no-tui --mode fast
```

The adapter duck-types the SDK — AgentGuardian never imports `openai-agents` as a runtime dependency, so the adapter works against whichever SDK version your project pins. The dispatch lives in `FRAMEWORK_ADAPTERS` in [`src/agent_guardian/cli.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py); the adapter implementation is in [`src/agent_guardian/adapters/framework/openai_agents.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/openai_agents.py).

## What next

- Step up complexity: [OpenAI Agents - support + tool (T3)](openai-agents-support-with-tool.md).
- The LangGraph mirror of this target: [LangGraph - simple chatbot (T4)](langgraph-simple-chatbot.md).
- Wire your own OpenAI Agents SDK target: [How-to - OpenAI Agents SDK](../how-to/wire-openai-agents.md).
