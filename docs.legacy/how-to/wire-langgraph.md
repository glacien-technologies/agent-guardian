# Wire LangGraph

**TL;DR.** Point AgentGuardian at a compiled LangGraph `StateGraph` and run a swarm scan in about ten minutes. Works today via the CLI (`--framework langgraph`) or the Python API (`LangGraphAdapter`).

## Prerequisites

- Python 3.10+.
- `pip install agent-guardian` (the wheel does **not** depend on LangGraph — the adapter duck-types the graph, see [`adapters/framework/langgraph.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/langgraph.py)).
- Your own LangGraph install (`pip install langgraph langchain-core` or whichever LangGraph version your agent pins).
- (Optional) To run the bundled demo target, clone the repo and run `uv sync --extra examples` — the `examples` extra is declared in [`pyproject.toml`](https://github.com/glacien-technologies/agent-guardian/blob/main/pyproject.toml) and pulls `langgraph`, `langchain-core`, and `langchain-google-genai`.

## How AgentGuardian sees a LangGraph

`LangGraphAdapter` wraps any object exposing `ainvoke(state)` (preferred) or `invoke(state)`. The state shape it sends is the conventional LangGraph `{"messages": [...]}` dict; the last message's `.content` is returned as the agent's reply. See [`adapters/framework/langgraph.py:27-81`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/langgraph.py).

The framework name registered on the CLI is `langgraph`. The mapping lives in `FRAMEWORK_ADAPTERS` in [`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py) and dispatch happens in `build_target_adapter` ([`cli.py:482-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

## Option A — CLI

Expose your compiled graph as a module-level attribute. The bundled demo does this in [`examples/langgraph/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/simple_chatbot.py):

```python
# examples/langgraph/simple_chatbot.py (excerpt)
from langgraph.graph import END, START, StateGraph

def build_graph():
    g: StateGraph = StateGraph(ChatState)
    g.add_node("respond", _respond)
    g.add_edge(START, "respond")
    g.add_edge("respond", END)
    return g.compile()

# Module-level handle that AgentGuardian's CLI imports.
graph = build_graph()
```

Then point the CLI at it via `--framework-ref MODULE:ATTR`:

```bash
agent-guardian scan \
  --framework langgraph \
  --framework-ref examples.langgraph.simple_chatbot:graph \
  --model openai:gpt-4o-mini \
  --mode fast
```

What each flag does:

- `--framework langgraph` — selects `LangGraphAdapter` from the registry ([`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--framework-ref MODULE:ATTR` — the CLI imports `MODULE` and reads `ATTR` off it ([`_resolve_framework_ref` in `cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). The colon form is preferred; the dotted form `MODULE.ATTR` is also accepted.
- `--model openai:gpt-4o-mini` — provider:model for the attacker/evaluator LLMs. Swap to `stub` for an offline dry-run, or to `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, or `bedrock:<id>` (see [`scan` help in `cli.py:2030-2037`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--mode fast` — caps each agent at 3 probes / 4 turns for a CI-gate smoke check (~45 s, ~$0.008). Drop the flag (or use `--mode full`) for a thorough scan. Semantics are documented inline in [`cli.py:2081-2093`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

To verify the wiring with no LLM credentials at all:

```bash
agent-guardian scan \
  --framework langgraph \
  --framework-ref examples.langgraph.simple_chatbot:graph \
  --model stub \
  --mode fast \
  --no-tui
```

The `stub` LLM ([`StubLLM` in the public API](../reference/api/index.md)) returns deterministic scripted responses — the run completes end-to-end with no API key, the AIVSS is **non-authoritative** (the stub does not actually attack), and you get a fully formed JSON / SARIF report you can inspect.

## Option B — Python API

If your graph lives inside an app you already drive from Python, skip the `MODULE:ATTR` indirection and construct the adapter directly:

```python
import asyncio

from agent_guardian import (
    LangGraphAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)
from my_app.graph import graph  # your compiled langgraph.StateGraph


async def main() -> None:
    adapter = LangGraphAdapter(graph)
    swarm = SwarmCommander(
        SwarmConfig(scan_id="langgraph-demo"),
        adapter,
        attacker_llm=StubLLM(),
        evaluator_llm=StubLLM(),
    )
    scan = await swarm.run()
    print(f"AIVSS={scan.aivss} band={scan.band} findings={len(scan.findings)}")


asyncio.run(main())
```

`SwarmCommander` is single-shot — call `.run()` once per instance ([`core/swarm.py:433-562`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py)). Swap `StubLLM()` for the real client of your choice (`OpenAIClient`, `AnthropicClient`, `GeminiClient`, `OllamaClient`, `BedrockClient`) once you want a real attack.

## What `MODULE:ATTR` accepts

- The attribute must be **module-level** — `_resolve_framework_ref` does an `importlib.import_module(module_name)` then walks the dotted `ATTR` with `getattr` ([`cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- Nested attributes work: `my_app.graph:builders.production_graph` resolves `builders.production_graph` on the `my_app.graph` module.
- **Import side-effects fire in the CLI process.** Logging setup, env-var reads, and any module-top-level `print()` happen exactly as if you ran your own script.
- The CLI calls the adapter as `LangGraphAdapter(native_obj, ref="MODULE:ATTR")` ([`cli.py:496-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). If the object you point at doesn't have `.ainvoke()` or `.invoke()`, the adapter raises `TypeError` with the exact missing methods ([`langgraph.py:36-40`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/langgraph.py)).

## Reading the report

The scan writes a signed JSON report by default (`--output json`); switch to SARIF for CI integrations with `--output sarif`. SARIF 2.1.0 compliance is enforced by [`reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py) and the contract test in [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py). See [Output formats](../reference/output-formats.md) for the full matrix.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--framework-ref 'foo.bar:graph': could not import module 'foo.bar'` | `MODULE` not importable from the CLI's `sys.path`. | `cd` into your project root (or set `PYTHONPATH`) so `python -c "import foo.bar"` works first. |
| `--framework langgraph: adapter rejected the object from 'mymod:graph': LangGraphAdapter expected a compiled graph with .ainvoke() or .invoke(); got StateGraph` | You exported the un-compiled `StateGraph`. | Call `.compile()` and export the compiled object. |
| `LangGraphAdapter: graph returned no 'messages' in its state` | Your graph's output state doesn't carry a `messages` list. | Wrap the node so the final state includes `{"messages": [..., AIMessage(...)]}` — the adapter pulls `result["messages"][-1].content` ([`langgraph.py:63-81`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/langgraph.py)). |
| `--framework-ref 'mymod.graph': could not import module 'mymod'` (dotted form) | Dotted form splits on the rightmost dot — so `mymod.graph` is parsed as module `mymod`, attribute `graph`. | Use the colon form: `mymod.graph:graph`. |
| Scan completes but every finding is from the stub script | You passed `--model stub`. | Use a real provider (e.g. `--model openai:gpt-4o-mini`) and export the matching API key. |

## See also

- [Framework adapter overview](../integrations/adapters/framework.md) — the full adapter matrix.
- [Scan modes](../concepts/scan-modes.md) — what `fast`, `smart`, `full` actually do.
- [CLI reference](../reference/cli.md) — every flag on every command.
- [Roadmap](../reference/roadmap.md) — what's planned for v1.1 (PydanticAI, Anthropic Claude Agent SDK).
