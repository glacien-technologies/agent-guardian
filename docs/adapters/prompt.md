# System Prompt Adapter (Mode A)

Use this adapter when all you have is the agent's system prompt — no
running endpoint, no source, no framework metadata. This is the
lowest-fidelity mode but the easiest to get started with.

## CLI

```bash
agent-guardian scan --system-prompt path/to/prompt.txt
```

The CLI is the recommended entry point. It wires up a `PromptAdapter`,
the resolved LLM client, and the swarm in one call.

## Programmatic

The library surface mirrors the CLI. Instantiate `PromptAdapter`
directly and hand it to `SwarmCommander`:

```python
import asyncio

from agent_guardian import (
    PromptAdapter,
    StubLLM,
    SwarmCommander,
    SwarmConfig,
)


async def main() -> None:
    adapter = PromptAdapter(
        prompt="You are a helpful customer-support bot for ACME Corp.",
        llm=StubLLM(),  # or OpenAIClient / AnthropicClient / GeminiClient / ...
        model="stub",
    )
    swarm = SwarmCommander(
        SwarmConfig(scan_id="demo"),
        adapter,
        attacker_llm=StubLLM(),
        evaluator_llm=StubLLM(),
    )
    scan = await swarm.run()
    print(scan.aivss, scan.band)


asyncio.run(main())
```

Swap `StubLLM()` for a real client (`OpenAIClient`, `AnthropicClient`,
`GeminiClient`, `BedrockClient`, `OllamaClient`) when you want to drive
the swarm with a hosted model.

## What gets detected

In Mode A the recon agent reads only the prompt text. It will detect:

- Explicitly declared tools in natural language ("you can issue refunds
  up to $50").
- Explicitly declared memory ("you remember user preferences across
  sessions").
- Explicitly declared inter-agent delegation ("you can hand off to the
  billing agent").

It will **not** detect anything that is not in the prompt — tools added
later via the framework, undocumented memory backends, or hidden agent
edges. For those, use the [Framework adapter](framework.md).

## When to use

- Pre-deployment review of a draft system prompt.
- Quick sanity check before wiring up the full agent.
- CI-time linting of every prompt change in your repo.
