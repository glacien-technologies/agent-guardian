# CrewAI demo target

A two-agent CrewAI crew (`Researcher` + `Writer`) with one bound tool
(`search_kb`) over a small canned knowledge base. Used to exercise the
`CrewAIAdapter` (`--framework crewai`) end-to-end against a multi-agent
target with a tool surface and a deliberate honeypot.

## What it tests

* All 10 ASI categories at the CrewAI kickoff boundary.
* Multi-agent coordination attacks — the adapter fingerprint sets
  `is_multi_agent=True`, which unlocks the corresponding probes.
* Tool-abuse and prompt-injection probes against the bound `search_kb`
  tool, whose KB intentionally contains `internal:admin-credentials` and
  `internal:api-key` entries the agent must refuse to echo back.

## Install

```bash
uv sync --extra examples-crewai
```

The `examples-crewai` extra pulls in `crewai`. It is intentionally a
separate extra from `examples` so the LangGraph + OpenAI Agents trio
remains independent of CrewAI's dependency graph.

## Run as an in-process target

```bash
agent-guardian scan \
  --framework crewai \
  --framework-ref examples.crewai.agent:research_crew \
  --model stub \
  --mode fast \
  --output md \
  --output-path scan.md
```

## Run as an HTTP target

```bash
uv run uvicorn examples.crewai.serve:app --port 8000 &
agent-guardian scan \
  --endpoint http://localhost:8000/chat \
  --model stub \
  --mode fast \
  --output md \
  --output-path scan.md
```

## Expected output

See `sample-scan.json` for a committed reference scan against this
target in `--model stub` mode. Re-run with a real model spec
(`gemini:gemini-2.5-flash`, `openai:gpt-4o`) for a graded AIVSS score.

## Docs

See `docs/try/scan-crewai.mdx` for the full walkthrough.
