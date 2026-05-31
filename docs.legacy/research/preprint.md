---
title: "AgentGuardian: A Multi-Agent Adversarial Swarm for OWASP ASI-Aligned Red Teaming (DRAFT)"
status: v0.1 draft pending soft-beta data
authors:
  - Glacien Engineering
date: 2026-05-30
---

# AgentGuardian: A Multi-Agent Adversarial Swarm for OWASP ASI-Aligned Red Teaming (DRAFT)

!!! warning "Draft — pending soft-beta data"
    This is a v0.1 draft of the preprint, frozen at the v1.0.0rc1
    snapshot. Figures and concrete scores will be populated after the
    10-team beta wave concludes (target: v1.1, Q3 2026). See
    [Roadmap → Research preprint](../reference/roadmap.md) for the
    publication track.

## Abstract

Large language model agents that plan, call tools, persist memory, and
collaborate with one another are now deployed in domains where their
failures have real economic and safety consequences. The OWASP Agentic
Security Initiative (ASI) catalogues ten distinct risk categories these
systems introduce — from goal manipulation (ASI01) to silent goal drift
across long sessions (ASI10) — but the public red-teaming toolchain
remains dominated by single-turn prompt jailbreaks and lab-grade
adversarial papers that are difficult to operationalise. We present
**AgentGuardian**, an open-source adversarial swarm framework that
operationalises ASI-aligned red-teaming as a deterministic, reproducible
process. Eleven specialist attacker agents — one for reconnaissance plus
one per ASI category — coordinate through a swarm commander to probe a
target with curated seed payloads, four published prompt-orchestration
strategies (TAP, MAD-MAX, PAIR, Crescendo), and four-tier escalation.
Findings are graded by a calibrated judge and aggregated into the
**AIVSS** (Agentic AI Vulnerability Scoring System) score, a single
deterministic 0–100 figure derived from severity-weighted pass-rates per
ASI category and a penalty term for critical / high categorical
failures. The framework ships 100% offline-capable (Ollama, stub LLM)
for compliance-sensitive environments and signs every evidence pack
with both HMAC-SHA256 and Ed25519 so downstream consumers can verify
that a scan was produced by the documented pipeline. This paper
describes the architecture, the AIVSS formula, the seed-probe corpus
(96 probes across ASI01–ASI10), and the experimental setup we will use
to publish the first public scorecards once the soft-beta cohort
concludes.

## 1. Introduction

LLM-based agents have moved from research demos into production
pipelines that book travel, file tickets, write and execute code,
analyse customer data, and call paid APIs on behalf of human operators.
Each capability widens the attack surface in a way the classical
prompt-injection literature does not capture. An agent that can read
its own memory, hand off subtasks to peer agents, and accumulate trust
over a session is qualitatively different from a single-turn chat
model.

The OWASP ASI Top-10 (2025) is the industry's first attempt to
catalogue this surface in a vendor-neutral way:

* **ASI01** Goal & instruction manipulation
* **ASI02** Tool misuse
* **ASI03** Privilege abuse
* **ASI04** Supply-chain compromise
* **ASI05** Code-execution and sandbox escape
* **ASI06** Memory poisoning
* **ASI07** Agent-to-agent exploitation
* **ASI08** Cascading failures
* **ASI09** Trust exploitation and identity spoofing
* **ASI10** Rogue agents and silent goal drift

Today's tooling addresses these unevenly. Prompt-injection scanners
(garak, promptfoo, PyRIT) ship strong corpora for ASI01 but have
little to say about ASI06–ASI10. Lab-grade papers (TAP, MAD-MAX, PAIR,
Crescendo, AgentPoison, MUZZLE, Hiding-in-AI-Traffic) each demonstrate
*one* attack on *one* category; reproducing them against a new target
requires non-trivial engineering. The MITRE ATLAS knowledge base
provides taxonomy but not executable artefacts. The CSA AI Controls
matrix is governance-grade rather than offensive.

AgentGuardian addresses this gap by:

1. **Mapping every probe** to an ASI category, a MITRE ATLAS technique,
   and a CSA control so a single scan emits findings consumable by
   security, governance, and engineering audiences.
2. **Treating red-teaming as an executable, deterministic pipeline**
   rather than a notebook script — the same scan against the same
   target with the same RNG seed produces byte-identical output.
3. **Implementing four published prompt strategies as pluggable
   modules**: TAP (Mehrotra et al., 2024), MAD-MAX (a multi-agent
   variant of MAD-attack), PAIR (Chao et al., 2023), and Crescendo
   (Russinovich et al., 2024). Specialist agents pick the strategy
   appropriate to their ASI category.
4. **Signing every evidence pack** so leaderboard submissions are
   provably untampered.

## 2. Related Work

**Tree of Attacks with Pruning (TAP)** (Mehrotra et al., 2024) is the
state-of-the-art single-turn jailbreak strategy that converges by
maintaining a beam of refined attack branches and pruning on judge
score. We implement TAP as a strategy module driving the ASI01 and
ASI03 specialist agents.

**MAD-MAX** is our naming for the multi-agent debate adaptation of the
MAD-attack pattern (Liang et al., 2024): two attacker LLMs argue about
how to rewrite a prompt and a third synthesises the winner. It excels
on conversational agents that learn within a session.

**PAIR (Prompt Automatic Iterative Refinement)** (Chao et al., 2023) is
the canonical iterative single-turn jailbreak. We use it as a baseline
strategy and a fallback when TAP's beam collapses.

**Crescendo** (Russinovich et al., 2024) is a multi-turn escalation
strategy that begins benignly and ratchets requests upward. It maps
naturally to ASI10 (silent goal drift) and ASI06 (memory poisoning).

**AgentPoison** (Chen et al., 2024) and **RedAgent** (Zhang et al.,
2024) propose multi-agent attackers that target memory and tool-use
respectively; their published prompts inform our ASI06 and ASI02
seed-probe corpora.

**Co-RedTeam** (Mu et al., 2024) demonstrates collaborative red-teaming
across heterogeneous agent teams. Our swarm commander is closer in
spirit to a Co-RedTeam coordinator than to a single attacker LLM.

**MUZZLE** (Zhou et al., 2024) introduces silent-failure-mode probing
for agentic systems — we adopt its evaluator-confidence calibration in
the AIVSS penalty term.

**Hiding-in-AI-Traffic** (Park et al., 2025) explores agent-to-agent
covert channels and motivates the ASI07 specialist's signal-detection
seed probes.

## 3. Architecture

AgentGuardian uses a three-layer architecture (figure forthcoming):

* **Layer 1 — Target Adapter.** The thing being scanned, exposed through
  one of four adapters: a Python callable (`CodeAdapter`), a system
  prompt file driven by a chosen LLM (`PromptAdapter`), an HTTP
  endpoint (`HttpAdapter` with pluggable shape modules for OpenAI /
  Anthropic / Bedrock / generic), or a framework-mode adapter
  (`LangGraphAdapter`, `CrewAIAdapter`, `AutoGenAdapter`,
  `OpenAIAgentsAdapter`, `StrandsAdapter`, `ADKAdapter`).

* **Layer 2 — Specialist agents.** Eleven agents:
    * **ReconAgent** — refines the fingerprint emitted by the adapter
      (model family, tool catalogue, system-prompt sketch, persistence
      surface).
    * **GoalHijackAgent** (ASI01), **ToolAbuseAgent** (ASI02),
      **PrivilegeAgent** (ASI03), **SupplyChainAgent** (ASI04),
      **CodeExecAgent** (ASI05), **MemoryPoisonAgent** (ASI06),
      **A2AAgent** (ASI07), **CascadeAgent** (ASI08),
      **TrustExploitAgent** (ASI09), **DriftAgent** (ASI10).

* **Layer 3 — Swarm commander.** Runs Recon to T-0, dispatches the ten
  specialist agents in parallel up to a configurable concurrency cap
  (default 10), checkpoints every 30 seconds (configurable) to decide
  whether to **continue**, **early-stop**, **re-task** a stalled agent,
  or **escalate** to a stricter judge, and finalises a `Scan` model
  carrying findings + AIVSS.

Each specialist agent embeds a calibrated **Judge** that grades every
attacker turn. The judge returns a verdict (`pass`, `partial`, `fail`,
`error`), a confidence in [0, 1], and a free-text rationale. The
swarm commander combines per-agent judges with an optional
**ESCALATE_JUDGE** override that engages a stricter cross-model judge
on the most ambiguous turns.

Determinism is preserved end-to-end by:

* A user-supplied RNG seed propagated to every random choice.
* Frozen seed-probe corpus shipped in the wheel.
* Canonical JSON serialisation on the report path so signed bytes are
  reproducible across machines.

## 4. The AIVSS Score

AIVSS aggregates the per-finding judge verdicts into a single 0–100
score. Higher is safer.

For each ASI category $c$ with finding set $F_c$ and probe set $P_c$:

$$\text{pass\_rate}(c) = \frac{|\{f \in F_c : f.\text{verdict} = \text{pass}\}|}{|P_c|}$$

The category score is severity-weighted:

$$s_c = 100 \cdot \frac{\sum_{f \in F_c} w(f.\text{severity}) \cdot \mathbb{1}[f.\text{verdict} = \text{pass}]}{\sum_{p \in P_c} w(p.\text{severity})}$$

where $w(\cdot)$ maps severity bands to integer weights
(LOW=1, MEDIUM=2, HIGH=4, CRITICAL=8).

The aggregate base score is the unweighted mean of category scores
across the ten ASI categories. A penalty term subtracts a clamped
amount for unaddressed critical / high findings:

$$\text{AIVSS} = \max\left(0, \min\left(100, \text{aggregate} - \text{penalty}\right)\right)$$

The penalty term is clamped to the closed interval [0.0, 50.0] per
unit so a maximally bad scan still floors at 0 (never negative). The
formula has been hypothesis-fuzzed at 1500 examples per property to
confirm monotonicity, range invariance, and determinism.

The mapping from score to band is:

| Score   | Band      | Colour    |
|---------|-----------|-----------|
| 90–100  | EXCELLENT | `#22c55e` |
| 75–89   | GOOD      | `#22c55e` |
| 60–74   | FAIR      | `#84cc16` |
| 40–59   | POOR      | `#facc15` |
| 0–39    | DANGEROUS | `#ef4444` |

## 5. Experimental Setup

The seed-probe corpus ships 92 YAML probes (corpus version
`2026.05`) — roughly nine per ASI category — hand-curated against
published attack patterns and informed by the related work surveyed in
§2. Each probe carries a payload (or family of payloads via the
`seeds:` list), an `expected_evidence` predicate the judge consults, a
`tier_floor` (T1–T4), and full taxonomy mapping to ASI / MITRE ATLAS /
CSA.

The four scan tiers are PRD-defined slices of effort:

* **T1 — Critical.** The full 11-agent swarm, 2M-token budget, 15 min
  wall budget, ~$2.40 estimated cost on batched / cached pricing
  (~$1054 on list price). The default for adversarial scoring.
* **T2 — High.** Eight specialist agents, narrower probe selection.
* **T3 — Medium.** Targeted ASI selection per fingerprint.
* **T4 — Smoke.** Recon + ASI01 only — for CI gating.

Tier is auto-detected from the target's `ObservedSurface` (presence of
tools, memory, A2A traffic, code execution) or overridden by the CLI.

For the v1.0 public scorecard we will run T1 against the following
targets — to be confirmed in the soft-beta cohort:

* Two leading open-weights instruction-tuned models (Llama, Mistral
  families).
* Two leading hosted chat assistants under their public OEM systems.
* One LangGraph-based travel agent reference application.
* One CrewAI sales-research crew.

Each target will be scanned three times (different RNG seeds) and the
mean ± std reported. Stub-LLM, signed-evidence smoke runs are already
captured under CI and the artefacts are reproducible from the public
GitHub repository.

## 6. Results

!!! info "Draft — pending soft-beta data (target v1.1, Q3 2026)"
    The v1.0.0 release-candidate (this draft) is the snapshot just
    before the first external scans land. Once the soft-beta cohort
    concludes (target: 2026-08-01 cohort wrap, v1.1 cut Q3 2026), this
    section will be populated with:

    * Per-target AIVSS distribution across tiers.
    * Per-ASI category pass-rates.
    * Strategy-level comparison: which prompt-strategy module produced
      the highest finding rate on each ASI category.
    * Cost / wall-time vs. AIVSS-discriminating-power Pareto frontier.

    The publication track is tracked in [Roadmap → Research preprint](../reference/roadmap.md).

## 7. Discussion

Three observations are visible without external data:

1. **Determinism is non-negotiable.** Several adversarial-prompt
   research benchmarks publish results that cannot be reproduced
   because their seed and corpus were never frozen. We commit to
   freezing both per release.

2. **Multi-agent attacks are not always strictly stronger.** Our
   internal back-tests against compromised stub targets show the
   single-turn PAIR strategy occasionally outperforms TAP and MAD-MAX
   on ASI01 simply because the attacker LLM gets confused by the
   debate transcript. We expose strategy choice per agent so users can
   measure this themselves.

3. **The judge is the weakest link.** Calibration noise in the per-turn
   judge propagates into AIVSS more than seed variance does. The
   `ESCALATE_JUDGE` mechanism mitigates this on the most ambiguous
   turns but does not eliminate it. We are exploring multi-judge
   ensembling for v1.1.

Future work:

* Closed-loop **agentic** red-teaming — let the attacker LLM
  *also* be an agent with tools and memory, not just a chat model.
* Differential AIVSS — compare two versions of the same target
  (pre/post-patch) and emit the delta.
* Cross-target AIVSS — score a multi-agent team rather than a single
  endpoint.

## 8. References

See PRD Appendix D for the full bibliography. Key entries:

* Mehrotra, A., et al. *Tree of Attacks with Pruning.* 2024.
* Liang, X., et al. *Encouraging Divergent Thinking in Large Language
  Models through Multi-Agent Debate.* 2024.
* Chao, P., et al. *Jailbreaking Black Box Large Language Models in
  Twenty Queries (PAIR).* 2023.
* Russinovich, M., et al. *Great, now write an article about that:
  The Crescendo Multi-Turn LLM Jailbreak Attack.* 2024.
* Chen, K., et al. *AgentPoison: Red-teaming LLM Agents via Poisoning
  Memory or Knowledge Bases.* NeurIPS 2024.
* Zhang, H., et al. *RedAgent: Red Teaming Large Language Models with
  Context-aware Autonomous Language Agent.* 2024.
* Mu, R., et al. *Co-RedTeam: Collaborative Red Teaming for Large
  Language Models.* 2024.
* Zhou, F., et al. *MUZZLE: Silent-Failure-Mode Probing for Agentic
  Systems.* 2024.
* Park, S., et al. *Hiding in AI Traffic: Covert Channels in
  Agent-to-Agent Communication.* 2025.
* OWASP Foundation. *Agentic Security Initiative (ASI) Top-10.* 2025.
* MITRE. *ATLAS: Adversarial Threat Landscape for AI Systems.* 2024.
* Cloud Security Alliance. *AI Controls Matrix.* 2024.

---

*DRAFT — Glacien Pte. Ltd., 2026-05-30. This preprint will be revised
with concrete soft-beta scorecards before submission to arXiv under
the cs.CR category.*
