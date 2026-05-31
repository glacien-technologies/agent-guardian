# OpenAI Agents - support + tool (T3)

**TL;DR.** The OpenAI Agents SDK mirror of the LangGraph T3 target: same `search_kb` tool, same canned KB with `internal:admin-credentials` and `internal:api-key` honeypots, no memory. Auto-detects to tier **T3**. Use it to exercise tool-abuse and prompt-injection probes through the SDK's `@function_tool` + `Runner` path.

## Prerequisites

Same as the [gallery](index.md#prerequisites): clone the repo, run `uv sync --extra examples --extra dev`, put `GEMINI_API_KEY=...` in `.env`.

## Source

Live file: [`examples/openai_agents/support_with_tool.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/support_with_tool.py).

```python
--8<-- "examples/openai_agents/support_with_tool.py"
```

The entry points:

- `agent` (line 59) — the `Agent` for `OpenAIAgentsAdapter` (Mode D), paired with `runner = Runner` (line 60).
- `run(prompt, *, session=None)` (line 63) — async callable for `CodeAdapter` (Mode B). `session` is accepted but unused.

The `_KB` honeypot (line 26) is byte-identical to the LangGraph T3 target's. Keeping the fixtures in lockstep across the two trios is deliberate — it makes scan-result comparisons between the LangGraph and OpenAI Agents adapters apples-to-apples.

## Scan it - Mode B (CodeAdapter)

```bash
agent-guardian scan examples.openai_agents.support_with_tool:run \
    --model stub --no-tui --mode fast
```

Expected final line:

```
scan cli-<id> done: AIVSS=n/a band=not_evaluated tier=T3 findings=0 report=/Users/<you>/.agentguardian/scans/cli-<id>/report.json
```

For an authoritative score (recommended on tool-using targets so the secret-extraction specialist can judge attempted exfiltration of `internal:*` entries):

```bash
agent-guardian scan examples.openai_agents.support_with_tool:run \
    --model gemini:gemini-2.5-flash --no-tui --mode smart
```

## Scan it - Mode D (OpenAIAgentsAdapter)

```bash
agent-guardian scan \
    --framework openai_agents \
    --framework-ref examples.openai_agents.support_with_tool:agent \
    --model stub --no-tui --mode fast
```

Mode D introspects the SDK's resolved tool registry on the `Agent` instance — see [`src/agent_guardian/adapters/framework/openai_agents.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/openai_agents.py). That gives the tool-scope-safety specialist a more accurate picture than the Mode B attribute heuristic.

## What to look for in the report

Same shape as the LangGraph T3 page — `sub_scores.tool_scope_safety`, `sub_scores.prompt_injection_resistance`, ASI02 + ASI01 findings. Canonical field reference: [`sample-scan.json`](sample-scan.json).

## What next

- The PII tier: [OpenAI Agents - PII assistant (T1)](openai-agents-personal-assistant-pii.md).
- The LangGraph mirror: [LangGraph - support + tool (T3)](langgraph-support-with-tool.md) — useful to diff scan results across frameworks.
- Wire your own OpenAI Agents target: [How-to - OpenAI Agents SDK](../how-to/wire-openai-agents.md).
