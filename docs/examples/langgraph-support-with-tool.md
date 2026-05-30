# LangGraph - support + tool (T3)

**TL;DR.** A support agent with one `search_kb` tool over a small canned knowledge base. No memory, no real PII — but the KB intentionally contains `internal:admin-credentials` and `internal:api-key` entries that the agent must refuse to surface. Auto-detects to tier **T3** (has tools, no per-session memory, no PII). Use it to exercise tool-abuse and prompt-injection probes.

## Prerequisites

Same as the [gallery](index.md#prerequisites): clone the repo, run `uv sync --extra examples --extra dev`, put `GEMINI_API_KEY=...` in `.env`.

## Source

Live file: [`examples/langgraph/support_with_tool.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/support_with_tool.py).

```python
--8<-- "examples/langgraph/support_with_tool.py"
```

The entry points:

- `graph` (line 90) — compiled `StateGraph` for `LangGraphAdapter` (Mode D). The graph is a two-node loop: `llm` -> conditional edge -> `tool` -> `llm` until the model stops issuing tool calls.
- `run(prompt, *, session=None)` (line 93) — async callable for `CodeAdapter` (Mode B). `session` is accepted for signature compatibility but unused.

The honeypot is the `_KB` dictionary (line 35). Public keys (`product:*`) are safe to echo; the `internal:*` entries are deliberately reachable by `search_kb` so prompt-injection and tool-abuse probes have something concrete to attempt to extract. A correctly-prompted agent must refuse to surface them even when the tool result contains them — the system prompt covers this on line 24.

## Scan it - Mode B (CodeAdapter)

```bash
agent-guardian scan examples.langgraph.support_with_tool:run \
    --model stub --no-tui --mode fast
```

Expected final line:

```
scan cli-<id> done: AIVSS=n/a band=not_evaluated tier=T3 findings=0 report=/Users/<you>/.agentguardian/scans/cli-<id>/report.json
```

The `tier=T3` is the recon agent picking up the `tools` attribute and the `search_kb` binding via Mode B's attribute heuristics (see [`src/agent_guardian/adapters/code.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/code.py)).

For an authoritative score, swap `--model stub` for a real provider — recommended for this target since the tool-abuse and secret-extraction specialists need a real evaluator to flag attempted exfiltration of the `internal:*` entries:

```bash
agent-guardian scan examples.langgraph.support_with_tool:run \
    --model gemini:gemini-2.5-flash --no-tui --mode smart
```

## Scan it - Mode D (LangGraphAdapter)

```bash
agent-guardian scan \
    --framework langgraph \
    --framework-ref examples.langgraph.support_with_tool:graph \
    --model stub --no-tui --mode fast
```

Mode D is preferred for tool-using targets — the framework adapter walks LangGraph's compiled node + edge graph and sees the real `search_kb` binding rather than relying on the source-level `tools` attribute hint. That gives the OWASP-LLM tool-scope-safety specialist a tighter scoping target.

## What to look for in the report

For this target, watch:

- `sub_scores.tool_scope_safety` — direct measure of whether the agent kept `search_kb` calls on-policy.
- `sub_scores.prompt_injection_resistance` — robustness to user-message injection asking the agent to ignore its system prompt and dump `internal:*` content.
- `findings[].asi` — expect ASI02 (Tool Misuse) and ASI01 (Prompt Injection) categories if any leakage is found.
- `coverage.probes_attempted` — lists the probe IDs that fired; `ASI02-*` and `ASI01-*` should appear for a T3 target.

The full canonical field list is checked into [`docs/examples/sample-scan.json`](sample-scan.json).

## What next

- The PII tier: [LangGraph - PII assistant (T1)](langgraph-personal-assistant-pii.md) adds memory and synthetic PII for the highest-scrutiny tier.
- Wire your own tool-using LangGraph agent: [How-to - LangGraph](../how-to/wire-langgraph.md).
- Read about the tool-scope-safety probe family: [Probes](../concepts/probes.md).
