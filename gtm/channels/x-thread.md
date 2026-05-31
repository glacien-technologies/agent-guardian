# X / Twitter — launch thread

**Account:** founder's account.
**Target time:** T-0, 15:00 UTC.
**Format:** 5-tweet thread. Embed the demo video in tweet 1 (X
algorithm boosts native video ~3x vs YouTube links).

## Tweet 1 (hook + native video)

```
I built an open-source red-teamer for AI agents.

Point it at your LangGraph / CrewAI / MCP / RAG / REST endpoint —
it deploys a swarm of 14 adversarial agents and finds prompt
injection, tool abuse, and memory exfiltration in under 5 minutes.

Apache-2.0. Demo ↓
[ATTACH: 60-second demo video, native upload — fallback link {{ YOUTUBE_DEMO_URL }}]
```

## Tweet 2 (the why)

```
The OSS market has great single-prompt scanners (garak, PyRIT,
Promptfoo) and great LLM evals (DeepEval, OpenAI evals).

What it didn't have: a multi-agent scanner that treats your agent
the way an attacker would — with tools, memory, and multi-step
reasoning all in scope.

AgentGuardian is that.
```

## Tweet 3 (the proof)

```
Live testbench, no install — five vulnerable agents you can scan in
your browser:

https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

Most viral demo: a LangGraph travel-concierge that exfiltrates
another user's PII through a prompt-injection in the memory tool.
AIVSS 8.4. Found in 4 minutes.
```

## Tweet 4 (the integration story)

```
Outputs SARIF (uploads to GitHub Code Scanning),
JSON / JUnit / Markdown / PDF.

Exit code 1 on high-risk findings → your CI gates on it.

GitHub Action shipping in v1.0.x. Docker image on GHCR. Pre-commit
hook. No telemetry.

`pip install agent-guardian` to try.
```

## Tweet 5 (the ask + the link)

```
Repo, docs, AIVSS formula — all here:
https://github.com/glacien-technologies/agent-guardian

The bit I would most value feedback on: the AIVSS dimension
weighting. Currently inverse-frequency from a small study; would
value a principled critique.

Stars and roasts equally welcome.
```

## Engagement plan

- Reply to every quote-tweet in the first 4 hours.
- Pin the thread for 7 days.
- If tweet 1 clears 100 retweets, run a follow-up thread on T+3 with
  "What I learned posting the AgentGuardian launch on HN, Reddit,
  Product Hunt, and X simultaneously."
