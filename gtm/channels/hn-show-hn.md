# Hacker News — Show HN

**Submit at:** https://news.ycombinator.com/submit
**Target time:** T-0, 13:00 UTC (08:00 ET, peak HN front-page traffic).

## Title (exact, 80 chars max)

```
Show HN: AgentGuardian – Open-source red teaming for AI agents
```

## URL field

```
https://github.com/glacien-technologies/agent-guardian
```

## Text field (HN allows a body when URL is set; keep under 200 words)

```
Hi HN — I have been building AgentGuardian, an open-source toolkit
that red-teams AI agents the way a security team red-teams a web app.

You point it at a LangGraph / CrewAI / MCP / RAG / REST endpoint and
it deploys a swarm of 14 specialist attackers — one per OWASP ASI
2026 category, plus A2A and cascading-failure agents — coordinated by
a Swarm Commander LLM. Every finding gets a deterministic 0–100 AIVSS
score and is triple-tagged to OWASP ASI, MITRE ATLAS v5.4.0, and the
CSA Agentic AI Red Teaming Guide. Output is SARIF, JSON, JUnit,
Markdown, or PDF; SARIF uploads cleanly into GitHub Code Scanning.

Live testbench (no install, no signup) — five vulnerable agents you
can scan in your browser:
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

60-second demo of the CLI flow (finds prompt injection in a LangGraph
travel-concierge agent and produces the evidence chain):
{{ YOUTUBE_DEMO_URL }}

Apache-2.0, local-first, no telemetry. `pip install agent-guardian`.

What I would most value feedback on: the AIVSS formula
(docs/reports/aivss-score) and which frameworks I should ship adapters
for next. Roasts welcome.
```

## First comment (post immediately after the submission goes live)

```
Some quick context that did not fit in the body:

* The swarm coordination is the part I am least sure I got right. The
  Commander uses convergence detection — if three agents independently
  find the same class of vulnerability with overlapping evidence, the
  remaining agents get re-tasked instead of duplicating. Open to better
  approaches.

* SARIF output was a hard requirement because the goal is "fail your
  CI on a high-risk finding the same way you fail it on a SAST hit",
  not "produce a PDF nobody reads". The exit-code matrix is at
  docs/reference/exit-codes.

* The closest comparable tools are garak (single-chain, LLM-only),
  Promptfoo (evals-first), and PyRIT (Microsoft's, single-chain).
  Comparison table at the top of the README. Happy to be told it is
  wrong.

* No telemetry, no phone-home, no account, no Cloud Run dependency.
  The testbench is hosted because some people want to click before
  they install; the tool itself never talks to us.
```

## What to do for the next 6 hours

1. Refresh the post every 10 minutes for the first hour. If it
   disappears from `/newest` without making it to the front page, do
   not re-submit — see `metrics.md` for the HN kill-switch.
2. Reply to every comment with a substantive answer within 30
   minutes. Use `response-templates.md` for the common ones.
3. If a comment points out a legitimate bug, file the GitHub issue
   immediately and reply with the issue number — that single act buys
   more credibility than any other interaction.
4. At T+2 h, post the second technical comment (a follow-up on
   whichever thread is busiest).

## What not to do

- Do not ask friends to upvote. HN's vote-ring detector is aggressive
  and bans accounts permanently. Organic only.
- Do not edit the title after posting. HN strips the post from the
  front page when titles are edited within the first hour.
- Do not link to the launch blog as the primary URL — the repo is the
  honest landing for a developer tool. Blog goes in the body.
