# Wire AWS Strands

**TL;DR.** Point AgentGuardian at an AWS Strands `Agent` and run a swarm scan in about ten minutes. Works today via the CLI (`--framework strands`) or the Python API (`StrandsAdapter`).

!!! note "Demo target status"
    There is no bundled Strands demo target in the `examples/` tree yet — only LangGraph and the OpenAI Agents SDK ship demo modules in v1.0. The Python wiring described below works today; a Strands demo target is tracked for v1.1 (see [Roadmap → v1.1](../reference/roadmap.md#v11-target-2026-q3-semver-11x)).

## Prerequisites

- Python 3.10+.
- `pip install agent-guardian` (the wheel does **not** depend on Strands — the adapter duck-types the agent, see [`adapters/framework/strands.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/strands.py)).
- Your own Strands install: `pip install strands-agents`.

## How AgentGuardian sees a Strands agent

`StrandsAdapter` accepts any object exposing `invoke_async(prompt)` (preferred), `invoke(prompt)`, or a callable `__call__(prompt)`. The result is stringified — many Strands return shapes expose `.message`, `.text`, `.output`, or `.response`, which the adapter probes in order. See [`adapters/framework/strands.py:24-81`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/strands.py).

The framework name registered on the CLI is `strands`. The mapping lives in `FRAMEWORK_ADAPTERS` in [`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py) and dispatch happens in `build_target_adapter` ([`cli.py:482-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

## Option A — CLI

Expose your agent as a module-level attribute:

```python
# my_app/strands_agent.py
from strands import Agent

# Module-level handle that AgentGuardian's CLI will import.
agent = Agent(
    name="support-bot",
    system_prompt="You are a customer-support agent for ...",
)
```

Then point the CLI at it:

```bash
agent-guardian scan \
  --framework strands \
  --framework-ref my_app.strands_agent:agent \
  --model openai:gpt-4o-mini \
  --mode fast
```

What each flag does:

- `--framework strands` — selects `StrandsAdapter` from the registry ([`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--framework-ref MODULE:ATTR` — the CLI imports `MODULE` and reads `ATTR` off it ([`_resolve_framework_ref` in `cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). The colon form is preferred; the dotted form `MODULE.ATTR` is also accepted.
- `--model openai:gpt-4o-mini` — provider:model for the attacker/evaluator LLMs (the swarm's LLMs, **not** your Strands agent's). Swap to `stub` for an offline dry-run, or to `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, or `bedrock:<id>` (see [`scan` help in `cli.py:2030-2037`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--mode fast` — caps each agent at 3 probes / 4 turns for a CI-gate smoke check (~45 s, ~$0.008). Drop the flag (or use `--mode full`) for a thorough scan. Semantics are documented inline in [`cli.py:2081-2093`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

To verify the wiring with no LLM credentials at all:

```bash
agent-guardian scan \
  --framework strands \
  --framework-ref my_app.strands_agent:agent \
  --model stub \
  --mode fast \
  --no-tui
```

The `stub` LLM returns deterministic scripted responses — the AIVSS is **non-authoritative** (the stub does not actually attack), and you get a fully formed report you can inspect.

## Option B — Python API

```python
import asyncio

from strands import Agent

from agent_guardian import (
    StrandsAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)


async def main() -> None:
    agent = Agent(name="support-bot", system_prompt="You are ...")
    adapter = StrandsAdapter(agent)
    swarm = SwarmCommander(
        SwarmConfig(scan_id="strands-demo"),
        adapter,
        attacker_llm=StubLLM(),
        evaluator_llm=StubLLM(),
    )
    scan = await swarm.run()
    print(f"AIVSS={scan.aivss} band={scan.band} findings={len(scan.findings)}")


asyncio.run(main())
```

`SwarmCommander` is single-shot — call `.run()` once per instance ([`core/swarm.py:433-562`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py)). Swap `StubLLM()` for a real client (`OpenAIClient`, `AnthropicClient`, `GeminiClient`, `OllamaClient`, `BedrockClient`) once you want a real attack.

## What `MODULE:ATTR` accepts

- The attribute must be **module-level**. `_resolve_framework_ref` does an `importlib.import_module(module_name)` then walks the dotted `ATTR` with `getattr` ([`cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- Nested attributes work: `my_app.agents:builders.production_agent` resolves `builders.production_agent` on the `my_app.agents` module.
- **Import side-effects fire in the CLI process.** Logging setup, env-var reads, and any module-top-level `print()` happen exactly as if you ran your own script.
- The CLI calls the adapter as `StrandsAdapter(native_obj, ref="MODULE:ATTR")` ([`cli.py:496-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). If the object exposes none of `{invoke_async, invoke, __call__}`, the adapter raises `TypeError` ([`strands.py:33-38`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/strands.py)).

## Reading the report

The scan writes a signed JSON report by default (`--output json`); switch to SARIF for CI integrations with `--output sarif`. SARIF 2.1.0 compliance is enforced by [`reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py) and the contract test in [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py). See [Output formats](../reference/output-formats.md) for the full matrix.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--framework-ref 'foo.bar:agent': could not import module 'foo.bar'` | `MODULE` not importable from the CLI's `sys.path`. | `cd` into your project root (or set `PYTHONPATH`) so `python -c "import foo.bar"` works first. |
| `--framework strands: adapter rejected the object from 'mymod:agent': StrandsAdapter expected an agent exposing .invoke_async()/.invoke()/__call__(); got <type>` | The pointed-at object isn't a Strands `Agent` or compatible callable. | Confirm `type(agent).__name__ == "Agent"` and that the Strands version you have exposes one of the three call surfaces. |
| `StrandsAdapter: agent returned None` | The agent returned `None` — usually an AWS credential or model-access issue swallowed upstream. | Run the agent once outside AgentGuardian first and confirm it returns a populated response. |
| Scan completes but every finding is from the stub script | You passed `--model stub`. | Use a real provider (e.g. `--model openai:gpt-4o-mini`) and export the matching API key. |

## See also

- [Framework adapter overview](../integrations/adapters/framework.md) — the full adapter matrix.
- [Scan modes](../concepts/scan-modes.md) — what `fast`, `smart`, `full` actually do.
- [CLI reference](../reference/cli.md) — every flag on every command.
- [Roadmap](../reference/roadmap.md) — what's planned for v1.1 (PydanticAI, Anthropic Claude Agent SDK, Strands demo target).
