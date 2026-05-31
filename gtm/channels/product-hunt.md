# Product Hunt — launch day

**Submit at:** https://producthunt.com/posts/new
**Target time:** Schedule for T-0, 00:01 UTC (Tuesday). Product Hunt
ranks by upvotes accumulated since 00:01 UTC; a US-morning launch
captures the West Coast wake-up and the EU lunch hour in one cycle.
**Maker:** the founder. Co-maker: the project's tech lead.

## Name

```
AgentGuardian
```

## Tagline (60 chars max)

```
Open-source red teaming for AI agents.
```

## Description (260 chars max)

```
Point it at your LangGraph, CrewAI, MCP server, RAG app, or REST
endpoint. It runs a swarm of 14 adversarial agents under a Swarm
Commander, produces an AIVSS 0–100 score mapped to OWASP ASI 2026,
and emits SARIF for your CI. Local-first, no telemetry.
```

## Topics (pick 3)

- Developer Tools
- Artificial Intelligence
- Open Source

## Gallery (in this order)

1. Hero image — terminal scan in progress (1270 × 760).
2. HTML report screenshot showing the AIVSS score + finding evidence.
3. The OWASP ASI 2026 + MITRE ATLAS + CSA triple-mapping panel.
4. The 60-second demo video — uploaded as a Product Hunt video, not
   linked to YouTube (PH ranks self-hosted video higher).

## First comment (maker comment, posted by the founder within
60 seconds of launch going live)

```
Maker here. I built AgentGuardian because I kept finding prompt-
injection bugs in agents by hand and got tired of it. The OSS market
has plenty of single-prompt scanners and plenty of LLM evals, but no
multi-agent swarm that treats an agent like an attacker would — with
tools, memory, and multi-step reasoning all in scope.

The fastest way to see what it does: open the live testbench at
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app — five
deliberately vulnerable agents you can scan in your browser, no
install. The 60-second video at the top of this PH page walks
through the LangGraph travel-concierge example end-to-end.

Apache-2.0. Local-first. No telemetry, no signup, no Cloud Run
dependency for the scanner itself.

The two things I would most value PH feedback on:

1. Is the AIVSS score immediately interpretable, or do you need the
   docs to make sense of it? (https://agentguardian.io/reports/aivss-score)

2. Which frameworks should I ship next? Currently shipping LangGraph,
   CrewAI, OpenAI Agents SDK, MCP servers, RAG apps, and REST. On the
   shortlist: ADK, AutoGen, Strands, Bedrock Agents.

Will be on the thread answering comments for the next 6 hours.

Repo: https://github.com/glacien-technologies/agent-guardian
Walkthrough video: {{ YOUTUBE_DEMO_URL }}
```

## Comment-response plan (first 6 hours)

Use `response-templates.md` for the recurring ones. The five most
likely comment categories:

1. "How is this different from PyRIT / garak / Promptfoo?" → template
   `R1` (comparison table link + the one-line distinction per tool).
2. "Does it work with my model?" → template `R2` (model-list + the
   stub mode for offline trials).
3. "Where does the AIVSS score come from?" → template `R3` (link to
   the formula + the one-line derivation).
4. "How do I integrate with CI?" → template `R4` (GitHub Action
   snippet + Docker image).
5. "Is the testbench safe to run locally?" → template `R5` (yes,
   sandboxed, see `examples/vulnerable-langgraph-agent`).

## Ship of the Day criteria

If the post is in the top 5 by 12:00 UTC, focus the maker time on the
PH thread. If it is below top 10 by 12:00 UTC, reallocate to HN +
Reddit per `metrics.md`.
