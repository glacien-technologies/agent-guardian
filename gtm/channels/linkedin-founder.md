# LinkedIn — founder post

**Account:** founder's personal account, not the Glacien company
page. LinkedIn's algorithm under-distributes company-page posts by
roughly 4x relative to personal posts.
**Target time:** T-0, 14:00 UTC (peak US weekday LinkedIn
engagement).
**Format:** native long-form post, no external image preview (the
algorithm penalises link previews; embed the demo video natively).

## Body (~400 words; LinkedIn caps at 3000 chars)

```
Today I am open-sourcing AgentGuardian — a swarm-based red-teaming
toolkit for AI agents. Apache-2.0, local-first, on PyPI today.

Why this matters now.

The 2024–2026 wave of AI agents — LangGraph, CrewAI, MCP servers, RAG
apps, OpenAI Agents SDK — moved fast. Production deployments are no
longer single-turn chatbots; they call tools, hold per-session
memory, talk to other agents, and execute code. The AppSec discipline
that grew up around web apps (SAST, DAST, SCA) does not cover any of
that.

The gap I kept hitting in client engagements: manual prompt-injection
testing does not scale, and the existing OSS scanners (garak, PyRIT,
Promptfoo) are excellent at single-prompt evaluation but were not
designed for multi-tool, multi-step agents. The attack surface of a
production agent is the joint space of (prompts × tools × memory ×
A2A topology), and a serial scanner under-explores it.

AgentGuardian is the answer I wish I had on those engagements.

What it does.

You point it at an agent (`--target my_app:graph --framework
langgraph` or `--endpoint http://localhost:8000/chat`). It deploys 14
specialist adversarial agents — one per OWASP ASI 2026 category, plus
A2A and cascading-failure attackers — coordinated by a Swarm
Commander LLM that does convergence detection. Every finding gets a
deterministic 0–100 AIVSS score and is triple-tagged with OWASP ASI
2026, MITRE ATLAS v5.4.0, and the CSA Agentic AI Red Teaming Guide.

Output is SARIF (uploads cleanly into GitHub Code Scanning), JSON,
JUnit, Markdown, or PDF. Exit codes are CI-gate-friendly.

How to try it in five minutes, no install.

Live testbench — five deliberately vulnerable agents you can scan in
your browser:
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

Sixty-second walkthrough — the LangGraph travel-concierge demo end
to end:
{{ YOUTUBE_DEMO_URL }}

Code, docs, and the AIVSS formula:
https://github.com/glacien-technologies/agent-guardian

What I would most value feedback on.

(1) The AIVSS dimension weighting (tool-call radius, memory-write
blast radius, A2A propagation potential). Currently inverse-frequency
from a small study; would value a principled derivation. (2) Which
frameworks should ship next — ADK, AutoGen, Strands, Bedrock Agents
are on the shortlist.

Open to critique. Apache-2.0; PRs welcome.
```

## Hashtags (LinkedIn allows up to 3 without engagement penalty)

```
#AISecurity #OpenSource #DevSecOps
```

## Engagement plan

- Reply to every comment in the first two hours, not later. LinkedIn
  ranks posts by "engagement velocity" in the first 90 minutes;
  late replies do not buy reach.
- Reshare from the Glacien company page after 4 hours, not before.
  Company-page reshare too early splits engagement and hurts both.
- Do not link the post in DMs. LinkedIn's spam classifier picks that
  up immediately.
