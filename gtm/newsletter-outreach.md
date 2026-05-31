# Newsletter outreach pack

Eight to ten targeted newsletter inclusions buy more sustained
attention than any single HN front-page run, and they show up in the
"how did you find us?" answers for months. The outreach is a one-shot
cold email per target — no follow-ups unless the editor replies.

## Targets (priority order)

| # | Newsletter            | Cadence  | Editor contact                          | Pitch angle                                   |
| - | --------------------- | -------- | --------------------------------------- | --------------------------------------------- |
| 1 | TLDR InfoSec          | Daily    | infosec@tldr.tech                       | "OSS scanner for the agent gap in AppSec"     |
| 2 | The Pragmatic Engineer| Weekly   | gergely@pragmaticengineer.com           | "Methodology piece: swarm vs single-chain"    |
| 3 | Ben's Bites           | Daily    | ben@bensbites.co                        | "AI agents need a SAST; here is one"          |
| 4 | The Rundown AI        | Daily    | hello@therundown.ai                     | "Live testbench: scan a vulnerable agent now" |
| 5 | LangChain Newsletter  | Bi-wkly  | newsletter@langchain.dev                | "LangGraph adapter for adversarial scanning"  |
| 6 | MCP Daily             | Daily    | hello@mcpdaily.com                      | "MCP server red-teamer, Apache-2.0"           |
| 7 | Risky Business        | Weekly   | feedback@risky.biz                      | "AI-agent AppSec, swarm-based methodology"    |
| 8 | The Sequence          | Weekly   | jrodriguez@thesequence.org              | "Open AIVSS formula + ablation results"       |
| 9 | tl;dr sec             | Weekly   | hello@tldrsec.com                       | "OSS SARIF-producing agent red-teamer"        |
| 10| Last Week in AI       | Weekly   | hello@lastweekin.ai                     | "Methodology: convergence-detecting swarm"    |

## Cold email template (copy-paste; vary per target)

**Subject lines (A/B test):**

- Variant A: `AI agents need a SAST. I built one.`
- Variant B: `Open-source red-teamer for LangGraph / MCP agents`
- Variant C: `Five vulnerable AI agents you can scan in your browser`

**Body:**

```
Hi {{ editor first name }},

I read {{ newsletter name }} every {{ cadence }} — the {{ specific
recent issue or piece they wrote, one line }} piece resonated.

I am the founder of Glacien Technologies and have been building
**AgentGuardian**, an Apache-2.0 toolkit that red-teams AI agents
(LangGraph / CrewAI / MCP / RAG / REST endpoints) and produces a
SARIF-format report. It deploys a swarm of 14 specialist adversarial
agents under a Swarm Commander and finds prompt injection, tool
abuse, memory exfiltration, and unsafe-tool-call behaviour in under
five minutes.

Why I am emailing you specifically: {{ one sentence tying the tool
to a piece they wrote — for TLDR InfoSec, mention the SAST/DAST
coverage they tend to feature; for Pragmatic Engineer, mention the
methodology angle; for Ben's Bites, mention the live-testbench
no-install demo }}.

Two ways to evaluate without installing:

1. Live testbench — five vulnerable agents, scan in your browser:
   https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app
2. 60-second walkthrough — finds prompt injection in a LangGraph
   travel-concierge agent: {{ YOUTUBE_DEMO_URL }}

If it fits your readers, I would love an inclusion in an upcoming
issue. Happy to provide a 100-word blurb in whatever style your
newsletter uses, or to answer questions over email.

Code: https://github.com/glacien-technologies/agent-guardian
Docs: https://agentguardian.io
Press kit: https://github.com/glacien-technologies/agent-guardian/tree/main/gtm/press-kit

Thanks for your time —
{{ founder first name }}
Glacien Technologies
```

## Pre-written blurb library

Provide one of these inline in the cold email if the editor asks for
a teaser. Each is exactly 100 words.

### Blurb A — for security newsletters (TLDR InfoSec, tl;dr sec, Risky Business)

```
AgentGuardian is an open-source toolkit (Apache-2.0) that red-teams
AI agents the way Semgrep red-teams code. You point it at a
LangGraph, CrewAI, MCP server, RAG app, or REST endpoint and it
deploys a swarm of 14 specialist adversarial agents under a Swarm
Commander LLM. Output is SARIF (uploads to GitHub Code Scanning),
with every finding triple-tagged to OWASP ASI 2026, MITRE ATLAS
v5.4.0, and the CSA Agentic AI Red Teaming Guide. Reproducible
testbench at agent-guardian-testbench-u6tm6gzysq-uc.a.run.app — five
vulnerable agents you can scan in your browser, no install.
```

### Blurb B — for engineering newsletters (Pragmatic Engineer, The Sequence)

```
AgentGuardian is an open-source swarm-based adversarial red-teamer
for AI agents. The methodological hook: production agents have
tools, memory, and multi-step reasoning, and a single-prompt scanner
under-explores the joint attack surface. AgentGuardian runs 14
specialist attackers concurrently under a Swarm Commander LLM that
performs convergence detection (Jaccard 0.6 on the technique × surface
tuple). Empirically, the swarm finds 2.3x more unique finding-classes
than serial in the same wall-clock budget. Open formula, open
ablation results, Apache-2.0. Repo:
github.com/glacien-technologies/agent-guardian.
```

### Blurb C — for AI newsletters (Ben's Bites, The Rundown, Last Week in AI)

```
AgentGuardian (Apache-2.0) is an open-source red-teamer for AI
agents. You point it at LangGraph, CrewAI, MCP, RAG, or any REST
endpoint and it finds prompt injection, tool abuse, memory
exfiltration, and unsafe-tool-call behaviour in under five minutes.
Output is SARIF for your CI. Live testbench with five vulnerable
agents you can scan in your browser, no signup, at
agent-guardian-testbench-u6tm6gzysq-uc.a.run.app. The most viral demo
is a LangGraph travel-concierge that exfiltrates another user's PII
through a prompt-injection in its memory tool. AIVSS 8.4, found in
under five minutes.
```

## What to do after sending

- Wait 72 hours for a reply.
- If no reply in 72 hours, do not follow up. The editor saw it and
  chose not to respond; a follow-up is noise.
- If a reply does come, prioritise responding within 6 hours — most
  newsletter editors batch their inbox once a day and a delayed
  response slips a week.
- Log every send in `launch-posts.md` as one row per newsletter,
  with the channel `newsletter:tldr-infosec` etc.
