# r/MachineLearning

**Sub:** https://reddit.com/r/MachineLearning
**Target time:** T+1, 14:00 UTC (peak r/MachineLearning weekday
engagement is mid-day US East Coast).
**Post type:** Self-post. Flair `[P]` for Project. The `[R]` flair is
reserved for paper releases — do not misuse it.

## Title

```
[P] AgentGuardian: swarm-based adversarial red-teaming for LLM agents (Apache-2.0)
```

## Body

```
**TL;DR.** Open-source toolkit that runs a coordinated swarm of 14
specialist adversarial agents against an LLM-based agent under test
(LangGraph / CrewAI / MCP / RAG / REST). Outputs an AIVSS 0–100 score
and a deterministic SARIF/JSON/JUnit report mapped to OWASP ASI 2026,
MITRE ATLAS v5.4.0, and the CSA Agentic AI Red Teaming Guide.

**The methodological hook.** Single-chain red-teamers (garak,
Promptfoo, PyRIT) sample one attack at a time. Production agents have
tool calls, memory, and multi-agent topologies — a serial probe under-
explores the joint attack surface. AgentGuardian runs 14 attackers
concurrently with a meta-agent (Swarm Commander) that performs
convergence detection: when three independent agents flag the same
finding-class with overlapping evidence, idle agents are re-tasked
instead of replicating. Convergence is operationalised as Jaccard
overlap on the (technique, target-surface) tuple > 0.6.

**The scoring.** AIVSS extends CVSS for agent-specific dimensions
(tool-call radius, memory-write blast radius, A2A propagation
potential). Formula is public, deterministic, and documented:
https://agentguardian.io/reports/aivss-score

**Empirical.** On the five-agent testbench (LangGraph travel-
concierge, RAG support-bot, MCP filesystem-server, OpenAI-Agents
coding-assistant, defended baseline):

- 4/5 vulnerable agents had a Critical (AIVSS >= 9.0) finding
  surfaced within 5 minutes wall-clock on the default `--mode fast`.
- The defended baseline ("clean_control") produced zero findings at
  AIVSS >= 7.0, which is the honest negative.
- Swarm vs serial ablation: the swarm found 2.3x more *unique*
  finding-classes (counting OWASP ASI category only once per class)
  in the same wall-clock budget.

Reproduce in browser: https://agent-guardian-testbench-u6tm6gzysq-uc.a.run.app

**Code + docs.** https://github.com/glacien-technologies/agent-guardian

**Pre-print.** A 12-page write-up of the methodology + ablation
results is at https://agentguardian.io/arxiv-preprint — not yet on
arXiv, that submission is pending endorsement.

**Demo walkthrough video.** {{ YOUTUBE_DEMO_URL }}

**What I am genuinely uncertain about.** (1) Convergence threshold —
0.6 Jaccard is hand-tuned, would love a principled derivation. (2)
AIVSS dimension weights — currently inverse-frequency from a small
study, not from a community vote. (3) Whether the swarm advantage
holds for very-low-context models — all empirical results above are
with Gemini 2.5 Flash as both target and attacker.

Critique very much welcome.
```

## r/MachineLearning rules to satisfy

- Posts must have technical substance; the `[P]` flair is strictly
  enforced. The body above states the methodological hypothesis,
  the operationalisation, the empirical result, and the open
  problems — that is the expected shape.
- No reposts within 30 days. If a previous Glacien post exists on
  this sub, check the archive before posting.
- Mods deprecate posts that read as product launches. Lead with the
  method, not the product.
