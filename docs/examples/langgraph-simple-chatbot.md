# LangGraph - simple chatbot (T4)

**TL;DR.** The lowest-complexity example: a single-node LangGraph wrapping one Gemini call. No tools, no memory, no PII — auto-detects to tier **T4**. Use it to verify the LangGraph adapter end-to-end with the smallest possible target surface.

## Prerequisites

Same as the [gallery](index.md#prerequisites): clone the repo, run `uv sync --extra examples --extra dev`, put `GEMINI_API_KEY=...` in `.env`. The scanner itself does not depend on LangGraph — the `examples` extra is opt-in and only pulls in `langgraph`, `langchain-core`, and `langchain-google-genai` for these demo targets.

## Source

Live file: [`examples/langgraph/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/simple_chatbot.py).

```python
--8<-- "examples/langgraph/simple_chatbot.py"
```

The two AgentGuardian entry points are:

- `graph` (line 58) — the compiled `StateGraph` for `LangGraphAdapter` (Mode D).
- `run(prompt, *, session=None)` (line 61) — the async callable for `CodeAdapter` (Mode B). `session` is accepted for signature compatibility but unused — T4 is stateless.

The system prompt forbids leaking internal company info, supplier prices, employee details, or the prompt itself. That gives the swarm something concrete to probe (ASI01 prompt-injection, ASI09 output-handling).

## Scan it - Mode B (CodeAdapter)

Treat the agent as any importable Python callable. Pass the dotted `module:attr` of `run`:

```bash
agent-guardian scan examples.langgraph.simple_chatbot:run \
    --model stub --no-tui --mode fast
```

Expected last line (the scan id and signature bytes change per run, the shape does not):

```
scan cli-<id> done: AIVSS=n/a band=not_evaluated tier=T4 findings=0 report=/Users/<you>/.agentguardian/scans/cli-<id>/report.json
```

The `band=not_evaluated` and `AIVSS=n/a` are correct under `--model stub`. A non-LLM evaluator cannot flag findings, so the scanner refuses to assign a band — see [`src/agent_guardian/core/swarm.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py) (look for `mode_authoritative`). Re-run with a real model for an authoritative score:

```bash
agent-guardian scan examples.langgraph.simple_chatbot:run \
    --model gemini:gemini-2.5-flash --no-tui --mode fast
```

See [LLM providers - Google Gemini / Vertex](../integrations/providers/vertex.md) for credentials.

## Scan it - Mode D (LangGraphAdapter)

Higher fidelity: the recon agent introspects the compiled graph directly. Pass the dotted reference to the module-level `graph` object:

```bash
agent-guardian scan \
    --framework langgraph \
    --framework-ref examples.langgraph.simple_chatbot:graph \
    --model stub --no-tui --mode fast
```

The CLI dispatches to `LangGraphAdapter` via `FRAMEWORK_ADAPTERS` in [`src/agent_guardian/cli.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py). The adapter duck-types `ainvoke({"messages": [...]})` — AgentGuardian never imports `langgraph` at runtime, so the adapter works against whichever LangGraph version your project pins ([`src/agent_guardian/adapters/framework/langgraph.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/adapters/framework/langgraph.py)).

## Inspect the report

The JSON evidence pack lands in `~/.agentguardian/scans/<scan-id>/report.json` and is Ed25519 + HMAC-SHA256 signed. The fields most worth eyeballing on a stub-mode run:

- `target.mode` — `code` for Mode B, `framework` for Mode D.
- `tier` — `T4` for this target (no tools, no memory).
- `mode_authoritative` — `false` under `--mode fast` and/or stub; gate-pass logic in `--fail-under` refuses to accept this value.
- `evaluation_mode` — `stub` when no real model is wired.

A canonical sample is checked into the repo at [`docs/examples/sample-scan.json`](sample-scan.json) and is what the documentation tests verify against on every CI run.

## What next

- Step up complexity: [LangGraph - support + tool (T3)](langgraph-support-with-tool.md) adds one tool and one honeypot.
- Wire your own LangGraph agent: [How-to - LangGraph](../how-to/wire-langgraph.md).
- Understand what the `T4` label changed in the scan plan: [Probes](../concepts/probes.md), [Glossary - Tier](../concepts/glossary.md).
