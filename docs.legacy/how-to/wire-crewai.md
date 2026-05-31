# Wire CrewAI

**TL;DR.** Point AgentGuardian at a CrewAI `Crew` and run a swarm scan in about ten minutes. Works today via the CLI (`--framework crewai`) or the Python API (`CrewAIAdapter`).

!!! note "Demo target status"
    There is no bundled CrewAI demo target in the `examples/` tree yet — only LangGraph and the OpenAI Agents SDK ship demo modules in v1.0. The Python wiring described below works today; a CrewAI demo target is tracked for v1.1 (see [Roadmap → v1.1](../reference/roadmap.md#v11-target-2026-q3-semver-11x)).

## Prerequisites

- Python 3.10+.
- `pip install agent-guardian` (the wheel does **not** depend on CrewAI — the adapter duck-types the crew, see [`adapters/framework/crewai.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/crewai.py)).
- Your own CrewAI install: `pip install crewai`.

## How AgentGuardian sees a Crew

`CrewAIAdapter` wraps any object exposing `kickoff_async(inputs=...)` (preferred) or `kickoff(inputs=...)`. The adapter calls it with `inputs={"input": prompt}` and stringifies the return value — newer CrewAI returns a `CrewOutput` with a `.raw` field, which the adapter prefers. See [`adapters/framework/crewai.py:24-70`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/crewai.py).

The framework name registered on the CLI is `crewai`. The mapping lives in `FRAMEWORK_ADAPTERS` in [`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py) and dispatch happens in `build_target_adapter` ([`cli.py:482-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

## Option A — CLI

Expose your built `Crew` as a module-level attribute:

```python
# my_app/crew.py
from crewai import Agent, Crew, Task

researcher = Agent(role="Researcher", goal="...", backstory="...")
task = Task(description="...", agent=researcher, expected_output="...")

# Module-level handle that AgentGuardian's CLI will import.
crew = Crew(agents=[researcher], tasks=[task])
```

Then point the CLI at it:

```bash
agent-guardian scan \
  --framework crewai \
  --framework-ref my_app.crew:crew \
  --model openai:gpt-4o-mini \
  --mode fast
```

What each flag does:

- `--framework crewai` — selects `CrewAIAdapter` from the registry ([`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--framework-ref MODULE:ATTR` — the CLI imports `MODULE` and reads `ATTR` off it ([`_resolve_framework_ref` in `cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). The colon form is preferred; the dotted form `MODULE.ATTR` is also accepted.
- `--model openai:gpt-4o-mini` — provider:model for the attacker/evaluator LLMs (the swarm's LLMs, **not** your crew's LLM). Swap to `stub` for an offline dry-run, or to `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, or `bedrock:<id>` (see [`scan` help in `cli.py:2030-2037`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--mode fast` — caps each agent at 3 probes / 4 turns for a CI-gate smoke check (~45 s, ~$0.008). Drop the flag (or use `--mode full`) for a thorough scan. Semantics are documented inline in [`cli.py:2081-2093`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

To verify the wiring with no LLM credentials at all:

```bash
agent-guardian scan \
  --framework crewai \
  --framework-ref my_app.crew:crew \
  --model stub \
  --mode fast \
  --no-tui
```

The `stub` LLM returns deterministic scripted responses — the AIVSS is **non-authoritative** (the stub does not actually attack), and you get a fully formed report you can inspect.

## Option B — Python API

If your crew lives inside an app you already drive from Python, construct the adapter directly:

```python
import asyncio

from crewai import Agent, Crew, Task

from agent_guardian import (
    CrewAIAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)


async def main() -> None:
    crew = Crew(agents=[...], tasks=[...])
    adapter = CrewAIAdapter(crew)
    swarm = SwarmCommander(
        SwarmConfig(scan_id="crewai-demo"),
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

- The attribute must be **module-level**. `_resolve_framework_ref` does an `importlib.import_module(module_name)` then walks the dotted `ATTR` with `getattr` ([`cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- Nested attributes work: `my_app.crews:builders.production_crew` resolves `builders.production_crew` on the `my_app.crews` module.
- **Import side-effects fire in the CLI process.** Logging setup, env-var reads, and any module-top-level `print()` happen exactly as if you ran your own script.
- The CLI calls the adapter as `CrewAIAdapter(native_obj, ref="MODULE:ATTR")` ([`cli.py:496-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). If the object doesn't have `.kickoff_async()` or `.kickoff()`, the adapter raises `TypeError` ([`crewai.py:33-37`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/crewai.py)).

## Reading the report

The scan writes a signed JSON report by default (`--output json`); switch to SARIF for CI integrations with `--output sarif`. SARIF 2.1.0 compliance is enforced by [`reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py) and the contract test in [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py). See [Output formats](../reference/output-formats.md) for the full matrix.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--framework-ref 'foo.bar:crew': could not import module 'foo.bar'` | `MODULE` not importable from the CLI's `sys.path`. | `cd` into your project root (or set `PYTHONPATH`) so `python -c "import foo.bar"` works first. |
| `--framework crewai: adapter rejected the object from 'mymod:crew': CrewAIAdapter expected a Crew with .kickoff_async() or .kickoff(); got <type>` | The pointed-at object isn't a CrewAI `Crew`. | Confirm `type(crew).__name__ == "Crew"` and that you exported the assembled crew, not an `Agent` or `Task`. |
| `CrewAIAdapter: crew returned None` | The crew's `kickoff` returned `None` — usually a misconfigured task or LLM auth error swallowed upstream. | Run the crew once outside AgentGuardian first and confirm it returns text. |
| Scan completes but every finding is from the stub script | You passed `--model stub`. | Use a real provider (e.g. `--model openai:gpt-4o-mini`) and export the matching API key. |

## See also

- [Framework adapter overview](../integrations/adapters/framework.md) — the full adapter matrix.
- [Scan modes](../concepts/scan-modes.md) — what `fast`, `smart`, `full` actually do.
- [CLI reference](../reference/cli.md) — every flag on every command.
- [Roadmap](../reference/roadmap.md) — what's planned for v1.1 (PydanticAI, Anthropic Claude Agent SDK, CrewAI demo target).
