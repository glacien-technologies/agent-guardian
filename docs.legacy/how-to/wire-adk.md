# Wire Google ADK

**TL;DR.** Point AgentGuardian at a Google ADK (Agent Development Kit) `Runner` and run a swarm scan in about ten minutes. Works today via the CLI (`--framework adk`) or the Python API (`ADKAdapter`).

!!! note "Demo target status"
    There is no bundled ADK demo target in the `examples/` tree yet — only LangGraph and the OpenAI Agents SDK ship demo modules in v1.0. The Python wiring described below works today; an ADK demo target is tracked for v1.1 (see [Roadmap → v1.1](../reference/roadmap.md#v11-target-2026-q3-semver-11x)).

## Prerequisites

- Python 3.10+.
- `pip install agent-guardian` (the wheel does **not** depend on `google-adk` — the adapter duck-types the runner, see [`adapters/framework/adk.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/adk.py)).
- Your own ADK install: `pip install google-adk`.

## How AgentGuardian sees an ADK runner

`ADKAdapter` accepts any object exposing one of:

- `run_async(input=...)` — preferred; result may be awaitable or an async iterator of events.
- `run(input=...)` — sync or async.
- `__call__(input=...)` — callable.

If the result is an async iterator (the upstream `Runner.run` contract yields events), the adapter drains it and concatenates text from each event's `text` / `content` / `delta` / `output` field. Non-streaming results probe the same fields plus `.message` and `.response`. See [`adapters/framework/adk.py:31-124`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/adk.py).

The framework name registered on the CLI is `adk`. The mapping lives in `FRAMEWORK_ADAPTERS` in [`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py) and dispatch happens in `build_target_adapter` ([`cli.py:482-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

## Option A — CLI

Expose your runner as a module-level attribute:

```python
# my_app/adk_runner.py
from google.adk import Agent, Runner

agent = Agent(name="support-bot", instruction="You are a customer-support agent for ...")

# Module-level handle that AgentGuardian's CLI will import.
runner = Runner(agent=agent)
```

Then point the CLI at it:

```bash
agent-guardian scan \
  --framework adk \
  --framework-ref my_app.adk_runner:runner \
  --model openai:gpt-4o-mini \
  --mode fast
```

What each flag does:

- `--framework adk` — selects `ADKAdapter` from the registry ([`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--framework-ref MODULE:ATTR` — the CLI imports `MODULE` and reads `ATTR` off it ([`_resolve_framework_ref` in `cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). The colon form is preferred; the dotted form `MODULE.ATTR` is also accepted.
- `--model openai:gpt-4o-mini` — provider:model for the attacker/evaluator LLMs (the swarm's LLMs, **not** your ADK agent's). Swap to `stub` for an offline dry-run, or to `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, or `bedrock:<id>` (see [`scan` help in `cli.py:2030-2037`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--mode fast` — caps each agent at 3 probes / 4 turns for a CI-gate smoke check (~45 s, ~$0.008). Drop the flag (or use `--mode full`) for a thorough scan. Semantics are documented inline in [`cli.py:2081-2093`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

To verify the wiring with no LLM credentials at all:

```bash
agent-guardian scan \
  --framework adk \
  --framework-ref my_app.adk_runner:runner \
  --model stub \
  --mode fast \
  --no-tui
```

The `stub` LLM returns deterministic scripted responses — the AIVSS is **non-authoritative** (the stub does not actually attack), and you get a fully formed report you can inspect.

## Option B — Python API

```python
import asyncio

from google.adk import Agent, Runner

from agent_guardian import (
    ADKAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)


async def main() -> None:
    agent = Agent(name="support-bot", instruction="You are ...")
    runner = Runner(agent=agent)
    adapter = ADKAdapter(runner)
    swarm = SwarmCommander(
        SwarmConfig(scan_id="adk-demo"),
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
- Nested attributes work: `my_app.runners:builders.production_runner` resolves `builders.production_runner` on the `my_app.runners` module.
- **Import side-effects fire in the CLI process.** Logging setup, env-var reads, and any module-top-level `print()` happen exactly as if you ran your own script.
- The CLI calls the adapter as `ADKAdapter(native_obj, ref="MODULE:ATTR")` ([`cli.py:496-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). If the object exposes none of `{run_async, run, __call__}`, the adapter raises `TypeError` ([`adk.py:40-44`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/adk.py)).

## A note on streaming

ADK's `Runner.run` upstream contract yields events. The adapter detects this and drains the iterator with `async for`, concatenating text parts in arrival order. If your runner produces no text events at all, the adapter raises `ValueError("ADKAdapter: event stream produced no text")` so the scan fails loudly rather than silently scoring an empty target ([`adk.py:81-90`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/adk.py)).

## Reading the report

The scan writes a signed JSON report by default (`--output json`); switch to SARIF for CI integrations with `--output sarif`. SARIF 2.1.0 compliance is enforced by [`reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py) and the contract test in [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py). See [Output formats](../reference/output-formats.md) for the full matrix.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--framework-ref 'foo.bar:runner': could not import module 'foo.bar'` | `MODULE` not importable from the CLI's `sys.path`. | `cd` into your project root (or set `PYTHONPATH`) so `python -c "import foo.bar"` works first. |
| `--framework adk: adapter rejected the object from 'mymod:runner': ADKAdapter expected a runner exposing .run_async()/.run()/__call__(); got <type>` | The pointed-at object isn't an ADK `Runner` or compatible callable. | Confirm you exported the `Runner`, not the bare `Agent`. |
| `ADKAdapter: event stream produced no text` | The runner streamed events but none carried `text` / `content` / `delta` / `output`. | Confirm your agent's tool / model is producing visible output; running the runner once outside AgentGuardian will surface the same issue. |
| `ADKAdapter: runner returned None` | Non-streaming path: runner returned `None`. | Usually a model-access or auth issue swallowed upstream — run the runner directly to confirm. |
| Scan completes but every finding is from the stub script | You passed `--model stub`. | Use a real provider (e.g. `--model openai:gpt-4o-mini`) and export the matching API key. |

## See also

- [Framework adapter overview](../integrations/adapters/framework.md) — the full adapter matrix.
- [Scan modes](../concepts/scan-modes.md) — what `fast`, `smart`, `full` actually do.
- [CLI reference](../reference/cli.md) — every flag on every command.
- [Roadmap](../reference/roadmap.md) — what's planned for v1.1 (PydanticAI, Anthropic Claude Agent SDK, ADK demo target).
