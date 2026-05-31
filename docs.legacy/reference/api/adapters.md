# Adapters

**TL;DR** — A `TargetAdapter` wraps an agent and exposes a uniform interface the swarm can drive: `fingerprint()`, `call(prompt, *, session=None)`, `aclose()`.

The single-turn `call(prompt, *, session=None)` shape lets one adapter contract cover both single-shot models (Mode A) and multi-turn frameworks (Mode D); adapters normalise framework-native conversation state behind `session`. See [`src/agent_guardian/adapters/base.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/base.py) for the abstract base, and [Framework adapters overview](../../integrations/adapters/index.md) for the user-facing concept tour.

## Base types

::: agent_guardian.adapters.base
    options:
      show_root_heading: false

## Prompt adapter (Mode A)

Wrap a system prompt around any `BaseLLM`. Use for pre-deployment prompt review when no agent runtime exists yet. See the [Scan a system prompt how-to](../../how-to/scan-a-system-prompt.md).

::: agent_guardian.adapters.prompt
    options:
      show_root_heading: false

## Code adapter (Mode B)

Wrap a Python callable (function, async function, class with `__call__`, or dotted-path string like `my_agent:run`). See the [Scan Python source how-to](../../how-to/scan-python-source.md).

::: agent_guardian.adapters.code
    options:
      show_root_heading: false

## HTTP adapter (Mode C)

Drive a hosted agent over HTTP. Supports OpenAI-Chat-Compatible, Anthropic-Messages-Compatible, and a generic chat-completion shape; pluggable via `agent_guardian.adapters.http_shapes`. See the [Scan an HTTP endpoint how-to](../../how-to/scan-an-http-endpoint.md).

::: agent_guardian.adapters.http
    options:
      show_root_heading: false

## Framework adapters (Mode D)

Auto-discovery wrappers for popular agent frameworks. Each normalises the framework's runtime object into the swarm-facing `TargetAdapter` shape. See [Framework adapter detail](../../integrations/adapters/framework.md) for the support matrix and per-framework wiring notes.

::: agent_guardian.adapters.framework
    options:
      show_root_heading: false
      members:
        - LangGraphAdapter
        - CrewAIAdapter
        - AutoGenAdapter
        - OpenAIAgentsAdapter
        - ADKAdapter
        - StrandsAdapter
        - FrameworkAdapter
