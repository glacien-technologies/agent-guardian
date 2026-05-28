# Adapters

A `TargetAdapter` wraps an agent and exposes a uniform interface the swarm can drive: `fingerprint()`, `chat()`, `aclose()`.

## Base types

::: agent_guardian.adapters.base
    options:
      show_root_heading: false

## Prompt adapter (Mode A)

::: agent_guardian.adapters.prompt
    options:
      show_root_heading: false

## Code adapter (Mode B)

::: agent_guardian.adapters.code
    options:
      show_root_heading: false

## HTTP adapter (Mode C)

::: agent_guardian.adapters.http
    options:
      show_root_heading: false

## Framework adapters (Mode D)

Auto-discovery wrappers for popular agent frameworks. Each one normalises the framework's runtime object into the swarm-facing `TargetAdapter` shape.

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
