# OpenAI Agents - PII assistant (T1)

**TL;DR.** OpenAI Agents SDK mirror of the LangGraph T1 target: three tools, a per-session notes store, synthetic PII fixtures. `has_tools + has_memory + touches_pii` auto-detects to tier **T1** — the highest scrutiny tier. Use it to exercise cross-session leakage, PII containment, and excessive-agency probes through the SDK.

## Prerequisites

Same as the [gallery](index.md#prerequisites): clone the repo, run `uv sync --extra examples --extra dev`, put `GEMINI_API_KEY=...` in `.env`.

## Source

Live file: [`examples/openai_agents/personal_assistant_pii.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/personal_assistant_pii.py).

```python
--8<-- "examples/openai_agents/personal_assistant_pii.py"
```

The entry points:

- `agent` (line 129) — the `Agent` for `OpenAIAgentsAdapter` (Mode D), paired with `runner = Runner` (line 130).
- `run(prompt, *, session=None)` (line 138) — async callable for `CodeAdapter` (Mode B). The `session` kwarg is load-bearing — it keys the per-user notes store. Without one, the target routes to a `"_anon"` bucket.

The `_CONTACTS` (line 34) and `_SESSION_NOTES` (line 72) dictionaries are byte-identical to the LangGraph T1 target's. All five contacts are synthetic — fake names, `example.com` emails, `555-` phone numbers, fabricated SSNs.

The marker attribute `memory = _SESSION_NOTES` (line 135) is surfaced so the recon agent's heuristics tag the target T1 even when routed through `OpenAIAgentsAdapter`. The SDK's tool registry on the `Agent` already exposes `lookup_contact`, `schedule_meeting`, `read_my_notes`, so the `tools` marker is not separately required for OpenAI Agents (whereas the LangGraph mirror needs it because the framework adapter does not walk the compiled graph for tool bindings).

## Scan it - Mode B (CodeAdapter)

```bash
agent-guardian scan examples.openai_agents.personal_assistant_pii:run \
    --model stub --no-tui --mode fast
```

Expected final line:

```
scan cli-<id> done: AIVSS=n/a band=not_evaluated tier=T1 findings=0 report=/Users/<you>/.agentguardian/scans/cli-<id>/report.json
```

Strongly recommended to switch to a real evaluator for T1 — cross-session leakage detection is judgement-heavy:

```bash
agent-guardian scan examples.openai_agents.personal_assistant_pii:run \
    --model gemini:gemini-2.5-flash --no-tui --mode smart
```

## Scan it - Mode D (OpenAIAgentsAdapter)

```bash
agent-guardian scan \
    --framework openai_agents \
    --framework-ref examples.openai_agents.personal_assistant_pii:agent \
    --model stub --no-tui --mode fast
```

## What to look for in the report

Same shape as the LangGraph T1 page — focus on `sub_scores.pii_containment`, `sub_scores.memory_poisoning_resistance`, and `sub_scores.excessive_agency_containment`. ASI06 and ASI07 specialists join the slate on T1 scans. Canonical field reference: [`sample-scan.json`](sample-scan.json).

## What next

- The LangGraph mirror: [LangGraph - PII assistant (T1)](langgraph-personal-assistant-pii.md). Same fixtures, different framework — useful for diffing scan outcomes across the two adapters.
- Wire your own OpenAI Agents target: [How-to - OpenAI Agents SDK](../how-to/wire-openai-agents.md).
- AIVSS sub-score weights for T1 targets: [AIVSS formula](../concepts/aivss.md).
