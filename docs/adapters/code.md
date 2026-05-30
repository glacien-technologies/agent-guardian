# Code Adapter (Mode B)

Use this adapter when you have a Python callable (function, async
function, or class instance with `__call__`) — typically your own agent
under test.

## CLI

Pass the callable as a dotted path of the form `module:attr`:

```bash
agent-guardian scan my_agent:run
```

The portion before `:` is the importable module; the portion after is
walked attribute-by-attribute. Classes are instantiated with no args.

## Programmatic

Instantiate `CodeAdapter` directly and hand it to `SwarmCommander`:

```python
import asyncio

from agent_guardian import (
    CodeAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)
from my_agents import my_agent_callable  # any sync/async callable


async def main() -> None:
    adapter = CodeAdapter(my_agent_callable)
    # Or from a dotted path:
    # adapter = CodeAdapter.from_dotted_path("my_agents:my_agent_callable")
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

`CodeAdapter` invokes the callable directly. Async callables are
awaited; sync callables run inside `asyncio.to_thread` so they do not
block the event loop. If the callable declares a `session` parameter the
adapter passes it on each turn.

## What gets detected

The code adapter inspects the supplied callable and any framework-style
attributes it carries:

- Declared tools via the conventional `tools` / `registered_tools` /
  `available_tools` attribute names.
- Declared memory via `memory` / `memory_store` / `state`.
- Multi-agent topology via `agents` / `crew_members` / `subagents` /
  `sub_agents`.

The recon agent then refines these tier hints during the live scan.
`CodeAdapter` does **not** statically grep your source tree — for
deeper code-graph analysis use a [Framework adapter](framework.md), or
combine this adapter with the [HTTP adapter](http.md) against a running
endpoint.

## When to use

- You can `import` the agent directly into your scan harness.
- You want the recon agent to introspect the real attribute set rather
  than infer from text.
- You are wiring AgentGuardian into a pytest suite that already has the
  agent's Python object in hand.
