# System Prompt Adapter (Mode A)

Use this adapter when all you have is the agent's system prompt — no
running endpoint, no source, no framework metadata. This is the
lowest-fidelity mode but the easiest to get started with.

## Usage

```bash
agent-guardian scan --system-prompt path/to/prompt.txt
```

Or pipe directly:

```bash
cat prompt.txt | agent-guardian scan --system-prompt -
```

## Programmatic

```python
from agent_guardian import scan_system_prompt

result = scan_system_prompt(
    prompt="You are a helpful customer-support bot for ACME Corp.",
    model="anthropic:claude-opus-4-7",
)
print(result.aivss_score, result.band)
```

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
