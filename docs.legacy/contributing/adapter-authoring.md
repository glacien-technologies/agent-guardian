# Authoring an adapter

> **TL;DR.** Two kinds of adapter ship: a `TargetAdapter` (the thing being scanned) and a `FrameworkAdapter` (a `TargetAdapter` subclass that knows about one agent framework's runtime objects). To add a new target shape you subclass `TargetAdapter` and implement `call` + `_fingerprint`. To add a new framework you subclass `FrameworkAdapter` and register it in `FRAMEWORK_ADAPTERS` so the CLI's `--framework <name>` flag dispatches to your class.

For the user-facing list of adapters that ship today see [Targets & Adapters → Framework](../integrations/adapters/framework.md). This page is the contribution mechanics.

## The base class

Every target mode AgentGuardian can scan implements
`agent_guardian.adapters.base.TargetAdapter`
(`src/agent_guardian/adapters/base.py:191-228`). The common contract is
"send one prompt, get back one text reply", with an opaque `session`
token threading multi-turn state.

The required surface is small:

```python
from agent_guardian.adapters.base import (
    ProfileEvidence,
    TargetAdapter,
    TargetFingerprint,
)


class MyAdapter(TargetAdapter):
    mode = "code"   # one of "prompt" | "code" | "http" | "framework"

    def __init__(self, ...):
        super().__init__()
        # REQUIRED: populate self._fingerprint or fingerprint() raises.
        self._fingerprint = TargetFingerprint(
            mode="code",
            ref="my-adapter:0.1",
            has_tools=False,
            has_memory=False,
            touches_pii=False,
            is_multi_agent=False,
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        ...

    def profile_evidence(self) -> ProfileEvidence:
        # White-box adapters override; default is black-box (call-only).
        return ProfileEvidence(box="black")

    async def aclose(self) -> None:
        # Release HTTP clients, framework runners, etc.
        return None
```

Four methods, three of them optional. The contract is documented inline
in `src/agent_guardian/adapters/base.py:191-228`.

### What recon does with the fingerprint

The recon agent walks the fingerprint *plus* whatever
`profile_evidence()` returns:

- `box="white"` plus a `text` payload (system-prompt source, in-process
  Python source, framework introspection dump) gets read directly.
- `box="black"` triggers behavioural probing — recon interrogates the
  target by `call()` instead of by reading.

So if your adapter has access to a tool catalogue, a system prompt, or
a memory schema, expose it via `profile_evidence(box="white", structured=...)`.
The recon agent will give noticeably stronger findings.

## Adding a framework adapter

Framework adapters are a subclass of `FrameworkAdapter`
(`src/agent_guardian/adapters/framework/base.py`), which is itself a
`TargetAdapter` with the `mode = "framework"` default and three
callback hooks (`AgentMessageCallback`, `ToolCallCallback`,
`MemoryWriteCallback`) the swarm uses to capture per-turn evidence.

### 1. Subclass `FrameworkAdapter`

Pattern your new class after the existing six adapters
(`src/agent_guardian/adapters/framework/{langgraph,crewai,autogen,openai_agents,strands,adk}.py`).
For a hypothetical `MyFramework` whose primitive is a compiled
`graph: MyFramework.Graph`:

```python
# src/agent_guardian/adapters/framework/myframework.py
from __future__ import annotations

from typing import Any

from agent_guardian.adapters.base import ProfileEvidence, TargetFingerprint
from agent_guardian.adapters.framework.base import FrameworkAdapter


class MyFrameworkAdapter(FrameworkAdapter):
    """Adapter for MyFramework's compiled-graph runtime."""

    def __init__(self, graph: Any) -> None:
        super().__init__()
        self._graph = graph
        self._fingerprint = TargetFingerprint(
            mode="framework",
            ref=f"myframework:{getattr(graph, 'name', 'graph')}",
            framework="myframework",
            has_tools=bool(getattr(graph, "tools", None)),
            has_memory=bool(getattr(graph, "memory", None)),
            declared_tools=[t.name for t in getattr(graph, "tools", [])],
        )

    async def call(self, prompt: str, *, session: str | None = None) -> str:
        result = await self._graph.ainvoke(
            {"input": prompt},
            config={"session_id": session} if session else None,
        )
        return result["output"]

    def profile_evidence(self) -> ProfileEvidence:
        # White-box: expose the tool graph as structured evidence.
        return ProfileEvidence(
            box="white",
            structured={
                "framework": "myframework",
                "tools": [t.name for t in getattr(self._graph, "tools", [])],
                "memory_keys": list(getattr(self._graph, "memory_keys", [])),
            },
        )

    async def aclose(self) -> None:
        close = getattr(self._graph, "aclose", None)
        if close is not None:
            await close()
```

### 2. Register in `FRAMEWORK_ADAPTERS`

`src/agent_guardian/cli.py:104-110` is the registry the CLI's
`--framework <name>` flag dispatches against. Add your class in
alphabetical order to keep the error messages deterministic:

```python
FRAMEWORK_ADAPTERS: dict[str, type[FrameworkAdapter]] = {
    "adk": ADKAdapter,
    "autogen": AutoGenAdapter,
    "crewai": CrewAIAdapter,
    "langgraph": LangGraphAdapter,
    "myframework": MyFrameworkAdapter,        # <-- added here
    "openai_agents": OpenAIAgentsAdapter,
    "strands": StrandsAdapter,
}
```

Also export from
`src/agent_guardian/adapters/framework/__init__.py` so users can
`from agent_guardian.adapters.framework import MyFrameworkAdapter`.

### 3. Use it from the CLI

```bash
agent-guardian scan \
  --framework myframework \
  --framework-ref my_app.graph:graph \
  --mode fast --seed 1
```

`--framework-ref MODULE:ATTR` is resolved by `_resolve_framework_ref`
in `cli.py` — your adapter receives the resolved object as its
constructor argument.

### 4. Tests

Drop fixtures under `tests/golden/adapters/myframework/` that exercise
the adapter against the stub LLM. A new framework adapter should also
add an end-to-end smoke under `tests/integration/adapters/` that
imports the real framework (gated behind `pytest.importorskip` so the
import doesn't block CI when the optional dep is missing).

## Adding a non-framework target adapter

If you are adding a *new target shape* (not a new framework), the four
existing modes (`prompt`, `code`, `http`, `framework`) cover most
ground — extending `TargetAdapter` directly is rare. The most likely
candidate is an MCP-server adapter (planned for v1.1, see [Roadmap](../reference/roadmap.md));
its pattern will look like an `HttpAdapter` with MCP-shaped
request/response framing.

## Submitting the PR

See [Contributing](index.md) for DCO, branch naming, and conventional
commits. An adapter PR is typically titled
`feat(adapters): add <framework>-adapter` and lands together with the
test fixtures and a row added to [Targets & Adapters → Framework](../integrations/adapters/framework.md).
