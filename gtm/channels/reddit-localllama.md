# r/LocalLLaMA

**Sub:** https://reddit.com/r/LocalLLaMA
**Target time:** T-0, 18:00 UTC (peak r/LocalLLaMA engagement is US
evening; EU and India still awake).
**Post type:** Self-post (text), not link-post. Link-posts hit
AutoModerator's "low-effort" filter on this sub.

## Title

```
I built an open-source swarm-based red-teamer for local LLM agents — finds prompt injection + tool abuse in <5 min
```

## Body

```
Sharing a thing I have been working on: **AgentGuardian**, an
Apache-2.0 toolkit that red-teams AI agents. Local-first — runs
against your Ollama / llama.cpp / vLLM endpoint with no phone-home.

Why a swarm instead of a single attack chain: production agents have
tools, memory, and multi-step reasoning. A single-prompt scanner
catches direct prompt injection and not much else. The swarm
approach runs 14 specialist attackers concurrently — recon → tool-
abuse → memory-poisoning → RAG-poisoning → A2A → cascading failure —
coordinated by a Swarm Commander LLM that re-tasks idle agents on
convergence.

What it works against today:

- LangGraph (compiled `StateGraph`)
- CrewAI agents
- OpenAI Agents SDK
- MCP servers
- RAG apps (any retriever interface)
- Plain REST endpoints
- Custom Python entrypoints (`module:function`)

Local model support — anything served on an OpenAI-compatible
endpoint, including Ollama (`ollama serve`), llama.cpp's
`llama-server`, vLLM, and LM Studio. The Swarm Commander itself can
be a local model — I have tested with Llama 3.3 70B and Qwen 2.5 32B.

Two ways to try it without installing:

1. Live testbench — five vulnerable agents in your browser:
   https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

2. 60-second CLI demo:
   {{ YOUTUBE_DEMO_URL }}

`pip install agent-guardian` to run locally. Docs at
https://agentguardian.io.

What I would love feedback on: which local-serving stacks I should
prioritise next (text-generation-webui? LiteLLM proxy?) and whether
the "Commander as a local model" path is genuinely usable for
non-frontier models. Roasts welcome.

Repo: https://github.com/glacien-technologies/agent-guardian
```

## AutoModerator notes

- r/LocalLLaMA AutoMod removes posts under 200 characters and posts
  with no flair. Flair this `Tutorial | Guide` or `Resources`.
- Self-promotion rule: cap link references at three. The post above
  has exactly three (testbench, demo video, docs).

## Engagement plan

- Stay on the thread for 2 hours after posting. r/LocalLLaMA upvote
  velocity peaks in the first 90 minutes.
- Pin a follow-up comment after the first hour with "Bonus: here is
  the exact Ollama command I used to point AgentGuardian at a local
  Llama 3.3 instance" — see `response-templates.md` for the
  Ollama-command snippet.
