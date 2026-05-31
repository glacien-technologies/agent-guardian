# r/netsec

**Sub:** https://reddit.com/r/netsec
**Target time:** T+3, 14:00 UTC.
**Post type:** **Link-post**, not self-post. r/netsec strictly
prefers link-posts to technical write-ups; self-posts get filtered.
The link goes to the deep-dive blog (owned by GTM-007).

## Title

```
Swarm-based adversarial red-teaming for LLM agents: methodology, AIVSS scoring, and a vulnerable LangGraph testbench
```

## URL field

```
https://agentguardian.io/blog/prompt-injection-in-agents
```

(Fallback if the deep-dive blog has not landed yet:
`https://github.com/glacien-technologies/agent-guardian` — but check
GTM-007 status before posting; the deep-dive is the canonical netsec
link.)

## First comment (post immediately after submission)

```
Author here. A few things that did not fit in the write-up:

* The swarm is 14 specialist agents (one per OWASP ASI 2026 category
  + A2A + cascading-failure) coordinated by a Swarm Commander that
  does convergence detection. The methodology section in the blog
  covers the convergence threshold (Jaccard 0.6 on technique × surface
  tuple) and the ablation results.

* SARIF output uploads cleanly into GitHub Code Scanning. The exit
  codes are gate-friendly: 1 on high-risk finding, 2 on scan error.

* The reproducible testbench is at
  https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app — five
  vulnerable agents, no signup, scans in your browser.

* Apache-2.0, local-first, no telemetry, no phone-home. The Cloud Run
  testbench is hosted because some people want to click before they
  install; the scanner itself never calls home.

The bit I would most value netsec critique on: the AIVSS dimension
weighting (tool-call radius, memory-write blast radius, A2A
propagation potential). Currently derived inverse-frequency from a
small study. Would value a principled critique.
```

## r/netsec rules to satisfy

- Submitter must be the author of the linked content. The deep-dive
  blog is byline-signed by the founder.
- No marketing language anywhere. Mods remove posts with phrases
  like "next-generation", "industry-leading", "comprehensive
  solution".
- Code links are expected; commercial pitches are removed.
