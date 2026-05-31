# Examples gallery

**TL;DR.** Six runnable LLM-backed framework targets (LangGraph and OpenAI Agents SDK, three tiers each), a Docker Compose recipe for the local dashboard, and a Colab reproducibility shim. Use these to verify your install end-to-end and to give AgentGuardian's adapters something concrete to scan.

## What's here

The gallery mirrors the [`examples/`](https://github.com/glacien-technologies/agent-guardian/tree/main/examples) tree in the repo. Each row below is a real, runnable file — no pseudocode.

| Framework         | Tier | What it exercises                                | Source                                                                                                                                  | Page                                                            |
| ----------------- | ---- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| LangGraph         | T4   | Single-node, no tools, no memory                 | [`langgraph/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/simple_chatbot.py)             | [LangGraph - simple chatbot](langgraph-simple-chatbot.md)       |
| LangGraph         | T3   | One tool (`search_kb`), no memory                | [`langgraph/support_with_tool.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/support_with_tool.py)       | [LangGraph - support + tool](langgraph-support-with-tool.md)    |
| LangGraph         | T1   | Three tools + per-session memory + PII           | [`langgraph/personal_assistant_pii.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/langgraph/personal_assistant_pii.py) | [LangGraph - PII assistant](langgraph-personal-assistant-pii.md) |
| OpenAI Agents SDK | T4   | Single agent, no tools, no memory                | [`openai_agents/simple_chatbot.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/simple_chatbot.py)     | [OpenAI Agents - simple chatbot](openai-agents-simple-chatbot.md) |
| OpenAI Agents SDK | T3   | One tool (`search_kb`), no memory                | [`openai_agents/support_with_tool.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/support_with_tool.py) | [OpenAI Agents - support + tool](openai-agents-support-with-tool.md) |
| OpenAI Agents SDK | T1   | Three tools + per-session memory + PII           | [`openai_agents/personal_assistant_pii.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/openai_agents/personal_assistant_pii.py) | [OpenAI Agents - PII assistant](openai-agents-personal-assistant-pii.md) |

Plus two non-target recipes:

- [Run the dashboard with Docker Compose](docker-compose-dashboard.md) — the bundled [`docker-compose.yml`](https://github.com/glacien-technologies/agent-guardian/blob/main/docker-compose.yml), front-to-back.
- [Reproduce in Colab](jupyter-quickstart.md) — an honest reproducibility shim for academic reviewers (AgentGuardian is a pipeline, not a notebook).

The tier labels follow AgentGuardian's auto-detect heuristic. T4 is prompt-only with no tools, memory, or PII; T3 adds tools; T1 adds tools *and* memory *and* PII. The [Glossary](../concepts/glossary.md) carries the canonical definitions, and the tier tags also bias which probes the swarm picks up — see [Probes](../concepts/probes.md).

## Prerequisites

The six framework targets are **not** runtime dependencies of `agent-guardian`. The scanner itself never imports `langgraph`, `langchain-core`, `openai`, or `openai-agents`. To run them, clone the repo and install the optional `examples` extra:

```bash
git clone https://github.com/glacien-technologies/agent-guardian.git
cd agent-guardian
uv sync --extra examples --extra dev
```

The six targets all call Gemini via Google's API. Put your key in `.env` at the repo root (it's gitignored):

```bash
echo "GEMINI_API_KEY=AIzaSy..." > .env
```

Source: [`examples/README.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/examples/README.md) is the canonical inventory; this gallery is the rendered view.

## Validate the install

Run the bundled smoke test — one benign prompt through each of the six targets. Cost is roughly $0.001 total (six ~100-token Gemini calls).

```bash
uv run python examples/_validate.py
```

Expected output: six `ok` lines and a final summary. If any target prints `ERR`, fix the install before moving on — none of the per-page scan recipes will work otherwise.

## Two ways to scan each target

Every target exposes two AgentGuardian entry points so you can pick the adapter that fits your workflow:

- **Mode B / `CodeAdapter`** — pass the dotted `module:attr` of the `run` coroutine. Fastest to wire up, no framework-specific introspection.
- **Mode D / framework adapter** — pass `--framework langgraph` (or `--framework openai_agents`) plus `--framework-ref module:attr` of the compiled `graph` or `agent`. Higher fidelity — the recon agent sees the real tool registry, memory backend, and graph edges.

The per-target pages list the exact commands. As a worked example, the T4 LangGraph chatbot scanned via Mode B looks like this:

```bash
agent-guardian scan examples.langgraph.simple_chatbot:run \
    --model stub --no-tui --mode fast
```

The `--model stub` flag is the deterministic offline backend — useful for verifying the pipeline without spending API credits. Real evaluation requires a real `--model` (see [LLM providers](../integrations/providers/index.md)). Stub-mode scans are explicitly marked **non-authoritative** in the report (the band reads `NOT_EVALUATED`, the AIVSS is retained only for debugging) — this is by design and documented at [`src/agent_guardian/core/swarm.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py).

## When to use which page

- **Just kicking the tyres** — start with [LangGraph - simple chatbot (T4)](langgraph-simple-chatbot.md). One file, one node, no tools.
- **Wiring AgentGuardian into a tool-using agent** — [LangGraph - support + tool (T3)](langgraph-support-with-tool.md) or [OpenAI Agents - support + tool (T3)](openai-agents-support-with-tool.md).
- **Stress-testing PII containment and cross-session isolation** — the T1 pages: [LangGraph](langgraph-personal-assistant-pii.md), [OpenAI Agents](openai-agents-personal-assistant-pii.md).
- **Running the dashboard without installing Python locally** — [Docker Compose](docker-compose-dashboard.md).
- **Reproducing the preprint** — [Colab](jupyter-quickstart.md).
