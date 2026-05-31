# r/cybersecurity

**Sub:** https://reddit.com/r/cybersecurity
**Target time:** T+2, 14:00 UTC.
**Post type:** Self-post. r/cybersecurity penalises link-only posts
hard. Flair `Education` or `News`, not `Career Questions`.

## Title

```
Open-source AI agent red-teamer (OWASP ASI 2026, MITRE ATLAS, CSA-mapped, SARIF output)
```

## Body

```
For the AppSec folks on this sub — a tool I have been building called
**AgentGuardian** (Apache-2.0). It treats an LLM-based agent
(LangGraph / CrewAI / MCP / RAG / REST endpoint) the way SAST treats a
codebase: you point it at the target, it produces a SARIF report your
GitHub Code Scanning UI can ingest, and CI gates on the AIVSS score.

**Why this matters for AppSec.** AI agents are entering production
without a SAST-equivalent. Manual prompt-injection testing does not
scale. Generic LLM evaluators (Promptfoo, DeepEval) test for hallu-
cination and format compliance, not for prompt-injection, tool abuse,
RAG poisoning, or memory exfiltration. The AppSec gap is real.

**What it does.**

1. Deploys a swarm of 14 specialist attackers — one per OWASP ASI
   2026 category, plus A2A (agent-to-agent) and cascading-failure
   agents. Coordinated by a Swarm Commander LLM that converges on
   findings instead of running them serially.
2. Produces a deterministic 0–100 AIVSS score (formula is open,
   documented at https://agentguardian.io/reports/aivss-score). Every
   finding is triple-tagged with OWASP ASI 2026, MITRE ATLAS v5.4.0,
   and the CSA Agentic AI Red Teaming Guide control IDs.
3. SARIF / JSON / JUnit / Markdown / PDF output. SARIF uploads
   cleanly into GitHub Code Scanning — no glue code. Exit codes are
   gate-friendly (1 = high-risk found, 2 = scan error).

**Integration story.** GitHub Action shipping in v1.0.x. Docker image
on GHCR (`ghcr.io/glacien-technologies/agent-guardian:latest`).
Pre-commit hook. No telemetry, no signup, no Cloud Run dependency —
local-first by design.

**Reproduce in 5 minutes (no install).**

Live testbench with five intentionally vulnerable agents:
https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

60-second walkthrough video:
{{ YOUTUBE_DEMO_URL }}

**Code.** https://github.com/glacien-technologies/agent-guardian

**The question I would value AppSec feedback on.** The OWASP ASI 2026
mapping is the bit I am least confident in — ASI 2026 is brand new
and the mapping of historical LLM-Top-10 categories into the ASI
taxonomy is partly editorial. If your team has reviewed ASI 2026,
I would value a hard look at `docs/attacks/overview` and a roast on
where I have miscategorised.
```

## r/cybersecurity rules to satisfy

- "No self-promotion" is enforced as `more than 1 link to your own
  domain per post`. The body above links the testbench
  (Cloud Run subdomain), the YouTube video (third-party), and the
  GitHub repo — counts as one own-domain link.
- "No FUD" rule — never frame the post as "your agents are at risk".
  Frame it as "here is a missing tool".
