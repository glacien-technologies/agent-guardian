# Wire the OpenAI Agents SDK

**TL;DR.** Point AgentGuardian at an OpenAI Agents SDK `Agent` and run a swarm scan in about ten minutes. Works today via the CLI (`--framework openai_agents`) or the Python API (`OpenAIAgentsAdapter`).

## Prerequisites

- Python 3.10+.
- `pip install agent-guardian` (the wheel does **not** depend on the OpenAI Agents SDK — the adapter duck-types the agent, see [`adapters/framework/openai_agents.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/openai_agents.py)).
- Your own SDK install: `pip install openai-agents`.
- (Optional) To run the bundled demo target, clone the repo and run `uv sync --extra examples` — the `examples` extra is declared in [`pyproject.toml`](https://github.com/glacien-technologies/agent-guardian/blob/main/pyproject.toml) and pulls `openai-agents` plus its peers.

## How AgentGuardian sees an OpenAI agent

`OpenAIAgentsAdapter` accepts either:

- an object that already exposes `run_async(input=...)` or `run(input=...)` directly (handy for tests), **or**
- an `Agent` instance paired with a `runner=` keyword (the canonical SDK pattern is `Runner.run(agent, input=...)`).

The adapter prefers the async path. The result's `.final_output` (string) is returned; if absent, it falls back to `result.messages[-1].content` or `str(result)`. See [`openai_agents.py:29-107`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/openai_agents.py).

The framework name registered on the CLI is `openai_agents`. The mapping lives in `FRAMEWORK_ADAPTERS` in [`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py) and dispatch happens in `build_target_adapter` ([`cli.py:482-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

## Option A — CLI

Expose your agent as a module-level attribute. The bundled demo does this in [`examples/openai_agents/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/simple_chatbot.py):

```python
# examples/openai_agents/simple_chatbot.py (excerpt)
from agents import Agent, OpenAIChatCompletionsModel, Runner

def _build_agent() -> Agent:
    client = make_openai_client_for_gemini()
    model = OpenAIChatCompletionsModel(model=MODEL_ID, openai_client=client)
    return Agent(name="glacien-coffee-bot", instructions=INSTRUCTIONS, model=model)

# Module-level handle that AgentGuardian's CLI imports.
agent = _build_agent()
```

Then point the CLI at it:

```bash
agent-guardian scan \
  --framework openai_agents \
  --framework-ref examples.openai_agents.simple_chatbot:agent \
  --model openai:gpt-4o-mini \
  --mode fast
```

What each flag does:

- `--framework openai_agents` — selects `OpenAIAgentsAdapter` from the registry ([`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--framework-ref MODULE:ATTR` — the CLI imports `MODULE` and reads `ATTR` off it ([`_resolve_framework_ref` in `cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). The colon form is preferred; the dotted form `MODULE.ATTR` is also accepted.
- `--model openai:gpt-4o-mini` — provider:model for the attacker/evaluator LLMs (the swarm's LLMs, **not** your agent's model). Swap to `stub` for an offline dry-run, or to `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, or `bedrock:<id>` (see [`scan` help in `cli.py:2030-2037`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--mode fast` — caps each agent at 3 probes / 4 turns for a CI-gate smoke check (~45 s, ~$0.008). Drop the flag (or use `--mode full`) for a thorough scan. Semantics are documented inline in [`cli.py:2081-2093`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

To verify wiring with no LLM credentials at all:

```bash
agent-guardian scan \
  --framework openai_agents \
  --framework-ref examples.openai_agents.simple_chatbot:agent \
  --model stub \
  --mode fast \
  --no-tui
```

The `stub` LLM returns deterministic scripted responses — the AIVSS is **non-authoritative** (the stub does not actually attack), and you get a fully formed report you can inspect.

## Option B — Python API

If your agent lives inside an app you already drive from Python, construct the adapter directly:

```python
import asyncio

from agents import Agent, Runner

from agent_guardian import (
    OpenAIAgentsAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)


async def main() -> None:
    agent = Agent(name="support-bot", instructions="You are a support agent for ...")
    adapter = OpenAIAgentsAdapter(agent, runner=Runner)
    swarm = SwarmCommander(
        SwarmConfig(scan_id="openai-agents-demo"),
        adapter,
        attacker_llm=StubLLM(),
        evaluator_llm=StubLLM(),
    )
    scan = await swarm.run()
    print(f"AIVSS={scan.aivss} band={scan.band} findings={len(scan.findings)}")


asyncio.run(main())
```

If your agent object already exposes `.run_async(input=...)` (some teams wrap `Runner.run` for ergonomics), you can drop the `runner=` keyword: `OpenAIAgentsAdapter(my_run_aware_agent)`. The adapter enforces that one of these surfaces is present ([`openai_agents.py:44-54`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/openai_agents.py)).

`SwarmCommander` is single-shot — call `.run()` once per instance ([`core/swarm.py:433-562`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py)). Swap `StubLLM()` for the real client of your choice (`OpenAIClient`, `AnthropicClient`, `GeminiClient`, `OllamaClient`, `BedrockClient`) once you want a real attack.

## What `MODULE:ATTR` accepts

- The attribute must be **module-level**. `_resolve_framework_ref` does an `importlib.import_module(module_name)` then walks the dotted `ATTR` with `getattr` ([`cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- Nested attributes work: `my_app.agents:builders.production_agent` resolves `builders.production_agent` on the `my_app.agents` module.
- **Import side-effects fire in the CLI process.** Logging setup, env-var reads, and any module-top-level `print()` happen exactly as if you ran your own script.
- The CLI calls the adapter as `OpenAIAgentsAdapter(native_obj, ref="MODULE:ATTR")` ([`cli.py:496-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). If the object doesn't expose `.run_async()` / `.run()` and no `runner=` was supplied, the adapter raises `TypeError` ([`openai_agents.py:44-54`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/openai_agents.py)). The CLI route does not pass `runner=`; if your agent doesn't carry `run_async`/`run` itself, wrap it in a tiny module-level adapter that does, or use the Python API.

## Reading the report

The scan writes a signed JSON report by default (`--output json`); switch to SARIF for CI integrations with `--output sarif`. SARIF 2.1.0 compliance is enforced by [`reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py) and the contract test in [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py). See [Output formats](../reference/output-formats.md) for the full matrix.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--framework-ref 'foo.bar:agent': could not import module 'foo.bar'` | `MODULE` not importable from the CLI's `sys.path`. | `cd` into your project root (or set `PYTHONPATH`) so `python -c "import foo.bar"` works first. |
| `--framework openai_agents: adapter rejected the object from 'mymod:agent': OpenAIAgentsAdapter needs either an agent exposing .run_async()/.run() or a Runner via runner=...; got Agent` | Your agent is a vanilla `Agent` and the CLI route can't accept a `runner=`. | Export a tiny module-level shim that exposes `run_async`, e.g. `async def run_async(input): return await Runner.run(agent, input=input)`, and point `--framework-ref` at it. Or use the Python API and pass `runner=Runner` explicitly. |
| `OpenAIAgentsAdapter: runner returned None` | The Runner returned `None` — usually a misconfigured model or auth error swallowed upstream. | Run the agent once outside AgentGuardian first and confirm it returns text. |
| Scan completes but every finding is from the stub script | You passed `--model stub`. | Use a real provider (e.g. `--model openai:gpt-4o-mini`) and export the matching API key. |

## See also

- [Framework adapter overview](../integrations/adapters/framework.md) — the full adapter matrix.
- [Scan modes](../concepts/scan-modes.md) — what `fast`, `smart`, `full` actually do.
- [CLI reference](../reference/cli.md) — every flag on every command.
- [Roadmap](../reference/roadmap.md) — what's planned for v1.1 (PydanticAI, Anthropic Claude Agent SDK).
