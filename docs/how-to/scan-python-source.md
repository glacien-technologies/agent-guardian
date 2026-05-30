# Scan Python source

**TL;DR:** point AgentGuardian at a Python callable
(`module:attr` dotted path) and the swarm will exercise it directly —
no HTTP, no serialization overhead. Async, sync, and `__call__`
class-instance targets are all supported.

## When to use this

- You can `import` the agent into your scan harness (your own code,
  your own monorepo, your own test suite).
- You want the recon agent to introspect the real Python attribute set
  (`tools`, `memory`, `agents`, …) rather than infer from prompt text.
- You are wiring AgentGuardian into a `pytest` suite that already has
  the agent's Python object in hand.

This is **Mode B** (Python callable) in the [adapter taxonomy](../integrations/adapters/index.md).
It is higher-fidelity than [Mode A](scan-a-system-prompt.md) because
the recon agent reads the source file, but is **not** a static
code-graph analysis — for deeper introspection use the framework
adapter (M8-partial in v1.0; see [roadmap](../reference/roadmap.md)) or pair
this adapter with [Mode C](scan-an-http-endpoint.md) against a running
endpoint.

## Prerequisites

- AgentGuardian installed (`pip install agent-guardian`).
- A Python callable, of one of the following shapes:
    1. A function — sync or `async`.
    2. A class with a default-constructible ctor and a `__call__`.
    3. A method or classmethod reachable via `module:Class.method`.
- The callable's package importable from your `PYTHONPATH` (i.e. you
  ran `pip install -e .` against your project, or you're in a `uv run`
  / `python -m` context where the path resolves).

## Run it (CLI)

`agent-guardian scan` takes a positional `TARGET` whose dotted form is
`module:attr` (see cli.py:1992–1995 and adapters/code.py:159–204).

The bundled
[`examples/langgraph/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/simple_chatbot.py)
ships exactly the right shape — an `async def run(prompt, *, session)` —
and is the smallest worked example in the repo.

```bash
# Smoke run with the stub LLM (no API keys, no money). Useful to
# verify the dotted path resolves and the callable shape is accepted.
agent-guardian scan examples.langgraph.simple_chatbot:run \
    --model stub \
    --no-tui \
    --mode fast

# Authoritative run — needs a real attacker + evaluator. The example
# itself reads GEMINI_API_KEY (via examples/_gemini_chat.py); the
# attacker / evaluator model is supplied separately:
export GEMINI_API_KEY=...
export OPENAI_API_KEY=sk-...
agent-guardian scan examples.langgraph.simple_chatbot:run \
    --model openai:gpt-4o-mini \
    --no-tui \
    --output sarif \
    --output-path agentguardian.sarif
```

`--model` here sets the *attacker + evaluator* model, **not** the
target's own LLM — the target makes its own LLM calls inside `run()`.

## Run it (Python)

```python
import asyncio

from agent_guardian import (
    CodeAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)
from examples.langgraph.simple_chatbot import run as target_run


async def main() -> None:
    # Either pass the callable directly:
    adapter = CodeAdapter(target_run)
    # …or use the dotted path:
    # adapter = CodeAdapter.from_dotted_path(
    #     "examples.langgraph.simple_chatbot:run"
    # )
    swarm = SwarmCommander(
        SwarmConfig(scan_id="demo"),
        adapter,
        attacker_llm=StubLLM(),
        evaluator_llm=StubLLM(),
    )
    scan = await swarm.run()
    print(scan.aivss, [f.summary for f in scan.findings])


asyncio.run(main())
```

`CodeAdapter.from_dotted_path` is `src/agent_guardian/adapters/code.py:107`.
The dotted-path resolver is `_resolve_dotted_path` (code.py:159) — it
walks `module:attr.subattr` chains and instantiates intermediate
classes with no-arg ctors when needed.

## How the adapter invokes your callable

The invocation rules are defined in `CodeAdapter.call` (adapters/code.py:121–145):

- **`async def`** — awaited directly.
- **Plain `def`** — run inside `asyncio.to_thread` so a slow sync
  target does not block the event loop.
- **Class instance with `__call__`** — `inspect.signature` unwraps
  `__call__` so async-vs-sync detection still works correctly.
- **`session` kwarg** — passed only if the callable's signature
  declares it (code.py:207–219). Mode B is otherwise stateless.
- **Non-`str` return** — coerced via `str(...)` with a
  `warnings.warn`, so you should return a `str` directly to avoid the
  noise (code.py:138–145).

## What the recon agent sees

`CodeAdapter` populates the target fingerprint by reading conventional
attribute names on the resolved callable (code.py:53–55):

| Tier hint           | Attribute names read                                        |
| :------------------ | :---------------------------------------------------------- |
| `has_tools`         | `tools`, `registered_tools`, `available_tools`              |
| `has_memory`        | `memory`, `memory_store`, `state`                           |
| `is_multi_agent`    | `agents`, `crew_members`, `subagents`, `sub_agents`         |

The recon agent then refines these hints during the live scan
(code.py:25–28). If your agent buries tools inside a runtime
registration that doesn't show up under those names, the recon agent
will still discover them during live probing, but the *fingerprint*
shown in the report may be a strict subset.

## Common errors

| Symptom                                                            | Cause + fix
| :---------------------------------------------------------------- | :----------
| `ValueError: dotted path must contain ':' separator`              | Use `module:attr`, not `module.attr` (code.py:162).
| `TypeError: CodeAdapter cannot instantiate ... with no args`      | The class needs constructor args. Wrap it: write a `def run(prompt): return MyClass(my_args).respond(prompt)` and point at the wrapper.
| `ModuleNotFoundError: ...`                                        | `pip install -e .` from your project root, or `cd` into the project before running `agent-guardian`.

## Next steps

- Wire the call into [GitHub Actions](integrate-github-actions.md) /
  [GitLab CI](integrate-gitlab-ci.md) / [Jenkins](integrate-jenkins.md)
  to gate every change.
- Read [Architecture](../concepts/architecture.md) for what the swarm actually
  does between recon and finalise.
- For a deployed target with no local code, see [Scan an HTTP
  endpoint](scan-an-http-endpoint.md).
