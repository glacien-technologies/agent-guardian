# Wire AutoGen

**TL;DR.** Point AgentGuardian at a Microsoft AutoGen `GroupChat` (or compatible agent) and run a swarm scan in about ten minutes. Works today via the CLI (`--framework autogen`) or the Python API (`AutoGenAdapter`).

!!! note "Demo target status"
    There is no bundled AutoGen demo target in the `examples/` tree yet — only LangGraph and the OpenAI Agents SDK ship demo modules in v1.0. The Python wiring described below works today; an AutoGen demo target is tracked for v1.1 (see [Roadmap → v1.1](../reference/roadmap.md#v11-target-2026-q3-semver-11x)).

## Prerequisites

- Python 3.10+.
- `pip install agent-guardian` (the wheel does **not** depend on AutoGen — the adapter duck-types the chat, see [`adapters/framework/autogen.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/autogen.py)).
- Your own AutoGen install: `pip install pyautogen` (0.2 series) or `pip install autogen-core autogen-agentchat` (0.4+).

## How AgentGuardian sees an AutoGen chat

`AutoGenAdapter` accepts anything with one of the following surfaces, in preference order:

1. `a_initiate_chat(message=...)` — async (AutoGen 0.2+).
2. `run_async(message=...)` — async (autogen-core 0.4+).
3. `initiate_chat(message=...)` — sync (AutoGen 0.2 fallback).
4. `run(message=...)` — sync (autogen-core 0.4 fallback).

The adapter unwraps the result by trying `.summary`, then `chat_history[-1]["content"]` (0.2-style `ChatResult`), then `.messages[-1].content` (0.4-style `TaskResult`), then `str(result)`. See [`adapters/framework/autogen.py:27-102`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/autogen.py).

The framework name registered on the CLI is `autogen`. The mapping lives in `FRAMEWORK_ADAPTERS` in [`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py) and dispatch happens in `build_target_adapter` ([`cli.py:482-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).

## Option A — CLI

Expose your group chat (or single agent with one of the surfaces above) as a module-level attribute:

```python
# my_app/chat.py
from autogen import AssistantAgent, GroupChat, GroupChatManager, UserProxyAgent

assistant = AssistantAgent(name="assistant", llm_config={...})
user_proxy = UserProxyAgent(name="user_proxy", code_execution_config=False)
manager = GroupChatManager(
    groupchat=GroupChat(agents=[assistant, user_proxy], messages=[], max_round=5)
)

# Module-level handle that AgentGuardian's CLI will import.
chat = manager
```

Then point the CLI at it:

```bash
agent-guardian scan \
  --framework autogen \
  --framework-ref my_app.chat:chat \
  --model openai:gpt-4o-mini \
  --mode fast
```

What each flag does:

- `--framework autogen` — selects `AutoGenAdapter` from the registry ([`cli.py:104-111`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--framework-ref MODULE:ATTR` — the CLI imports `MODULE` and reads `ATTR` off it ([`_resolve_framework_ref` in `cli.py:114-158`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). The colon form is preferred; the dotted form `MODULE.ATTR` is also accepted.
- `--model openai:gpt-4o-mini` — provider:model for the attacker/evaluator LLMs (the swarm's LLMs, **not** your AutoGen agents'). Swap to `stub` for an offline dry-run, or to `anthropic:claude-haiku-4-5`, `gemini:gemini-2.5-flash`, `ollama:llama3.1`, or `bedrock:<id>` (see [`scan` help in `cli.py:2030-2037`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)).
- `--mode fast` — caps each agent at 3 probes / 4 turns for a CI-gate smoke check (~45 s, ~$0.008). Drop the flag (or use `--mode full`) for a thorough scan. Semantics are documented inline in [`cli.py:2081-2093`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py).

To verify the wiring with no LLM credentials at all:

```bash
agent-guardian scan \
  --framework autogen \
  --framework-ref my_app.chat:chat \
  --model stub \
  --mode fast \
  --no-tui
```

The `stub` LLM returns deterministic scripted responses — the AIVSS is **non-authoritative** (the stub does not actually attack), and you get a fully formed report you can inspect.

## Option B — Python API

```python
import asyncio

from agent_guardian import (
    AutoGenAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)


async def main() -> None:
    chat = build_my_groupchat()  # your AutoGen chat/manager
    adapter = AutoGenAdapter(chat)
    swarm = SwarmCommander(
        SwarmConfig(scan_id="autogen-demo"),
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
- Nested attributes work: `my_app.chats:builders.production_chat` resolves `builders.production_chat` on the `my_app.chats` module.
- **Import side-effects fire in the CLI process.** Logging setup, env-var reads, and any module-top-level `print()` happen exactly as if you ran your own script.
- The CLI calls the adapter as `AutoGenAdapter(native_obj, ref="MODULE:ATTR")` ([`cli.py:496-506`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py)). If the object exposes none of `{a_initiate_chat, initiate_chat, run_async, run}`, the adapter raises `TypeError` ([`autogen.py:36-43`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/autogen.py)).

## Reading the report

The scan writes a signed JSON report by default (`--output json`); switch to SARIF for CI integrations with `--output sarif`. SARIF 2.1.0 compliance is enforced by [`reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py) and the contract test in [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py). See [Output formats](../reference/output-formats.md) for the full matrix.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--framework-ref 'foo.bar:chat': could not import module 'foo.bar'` | `MODULE` not importable from the CLI's `sys.path`. | `cd` into your project root (or set `PYTHONPATH`) so `python -c "import foo.bar"` works first. |
| `--framework autogen: adapter rejected the object from 'mymod:chat': AutoGenAdapter expected a chat/agent with one of {a_initiate_chat, initiate_chat, run_async, run}; got <type>` | The pointed-at object isn't an AutoGen chat or compatible agent. | Export the `GroupChatManager` (0.2) or the runnable team (0.4) — not the bare `GroupChat` dataclass. |
| `AutoGenAdapter: chat returned None` | The chat returned `None` — usually a misconfigured LLM in `llm_config`. | Run the chat once outside AgentGuardian first and confirm it returns a `ChatResult` / `TaskResult` with text. |
| Scan completes but every finding is from the stub script | You passed `--model stub`. | Use a real provider (e.g. `--model openai:gpt-4o-mini`) and export the matching API key. |

## See also

- [Framework adapter overview](../integrations/adapters/framework.md) — the full adapter matrix.
- [Scan modes](../concepts/scan-modes.md) — what `fast`, `smart`, `full` actually do.
- [CLI reference](../reference/cli.md) — every flag on every command.
- [Roadmap](../reference/roadmap.md) — what's planned for v1.1 (PydanticAI, Anthropic Claude Agent SDK, AutoGen demo target).
