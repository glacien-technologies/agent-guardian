---
title: How AgentGuardian compares
---

# How AgentGuardian compares to other red-teaming tools

> **TL;DR.** AgentGuardian is the first open-source toolkit built around a *multi-agent adversarial swarm* aligned to the OWASP Agentic Security Initiative (ASI Top-10), emitting a deterministic 0–100 AIVSS score and HMAC + Ed25519-signed evidence packs. Other tools in the space (Promptfoo, garak, PyRIT, Mindgard, Inspect, DeepTeam) each cover slices of the same problem; this page lays them out side-by-side, fact-checked against their own docs as of the date below.

*Last verified: 2026-05-30.*

## Why we still respect these tools

Every project in the table below is independently useful. Promptfoo's prompt-eval matrix is the de-facto standard for single-turn jailbreak testing. garak's plugin model is what every red-teaming framework is measured against. PyRIT's risk-identification taxonomy shaped a generation of LLM security thinking — its archival in 2026 was an explicit pivot to Microsoft AI Red Team's hosted evaluation product, not a repudiation of the framework. Mindgard ships a polished commercial experience. Inspect's eval primitives are the cleanest in the field. DeepTeam was the first to operationalise OWASP LLM Top-10 in a notebook-friendly form.

AgentGuardian's bet is that *agentic* AI — tools, memory, A2A, persistence — needs a framework whose unit is "a swarm of attackers per ASI category" rather than "one attacker per prompt", and that the scoring + signing layer is the bit the rest of the ecosystem will eventually agree on.

## Feature matrix

| Tool                    | Multi-agent swarm | Agentic-AI focus     | Standards aligned                              | Open formula   | Signed evidence packs   | 0–100 score             | License                | Maintained                   |
| ----------------------- | ----------------- | -------------------- | ---------------------------------------------- | -------------- | ----------------------- | ----------------------- | ---------------------- | ---------------------------- |
| **AgentGuardian**       | Yes               | Yes                  | OWASP ASI + MITRE ATLAS + CSA AICM             | Yes            | HMAC + Ed25519          | AIVSS 0–100             | Apache-2.0             | Active                       |
| Promptfoo               | No                | Partial              | MITRE ATLAS                                    | Partial        | No                      | Pass / fail per assert  | MIT                    | Active                       |
| garak                   | No                | Partial              | Probe taxonomy (internal)                      | Partial        | No                      | Per-probe rate          | Apache-2.0             | Active                       |
| Microsoft PyRIT         | No                | Partial              | PyRIT risk taxonomy                            | Yes            | No                      | Scorer-defined          | MIT                    | **Archived 2026-03-27**      |
| Mindgard                | No                | Yes                  | Proprietary                                    | No (closed)    | No                      | Proprietary score       | Proprietary SaaS       | Active                       |
| UK AISI Inspect         | No (eval-first)   | Partial              | Eval primitives                                | Yes (per-eval) | No                      | Per-eval                | MIT                    | Active                       |
| DeepTeam                | No                | Partial              | OWASP LLM Top-10                               | Yes            | No                      | Vulnerability count     | Apache-2.0             | Active                       |

## Sources

Each row above was fact-checked against the project's own documentation on 2026-05-30. If you spot drift, open an issue at <https://github.com/glacien-technologies/agent-guardian/issues> and we will re-verify.

- **AgentGuardian** — eleven specialist agents driven by a swarm commander
  ([`src/agent_guardian/agents/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/agents),
  [`src/agent_guardian/core/`](https://github.com/glacien-technologies/agent-guardian/tree/main/src/agent_guardian/core));
  probes tagged across OWASP ASI + MITRE ATLAS + CSA AICM (see
  [Concepts → Probes](../concepts/probes.md));
  open AIVSS formula ([Concepts → AIVSS Score](../concepts/aivss.md));
  HMAC + Ed25519 signing of every JSON report
  ([Security → Signing & verification](../security/signing.md)).
- **Promptfoo** — MITRE ATLAS plugin documented at
  <https://www.promptfoo.dev/docs/red-team/mitre-atlas/> (verified 2026-05-30);
  MIT license declared in
  <https://github.com/promptfoo/promptfoo/blob/main/LICENSE>.
- **garak** — project home <https://github.com/NVIDIA/garak>; Apache-2.0
  license declared in <https://github.com/NVIDIA/garak/blob/main/LICENSE>.
- **Microsoft PyRIT** — repository <https://github.com/microsoft/PyRIT>;
  the repository's `README.md` header now reads "Archived" and the
  final commit is dated 2026-03-27. The successor is the
  Azure-AI-Studio "AI Red Team" hosted feature.
- **Mindgard** — closed-source commercial SaaS product
  (<https://mindgard.ai>); not redistributable, no open scoring
  formula.
- **UK AISI Inspect** — <https://github.com/UKGovernmentBEIS/inspect_ai>;
  MIT licensed. Inspect is eval-first with agent primitives; running a
  full red-team requires composing the primitives yourself.
- **ConfidentAI DeepTeam** — <https://github.com/confident-ai/deepteam>;
  Apache-2.0; aligned to OWASP LLM Top-10 (not ASI Top-10).

## What the columns mean

**Multi-agent swarm.** Whether attacks are driven by a coordinated *team* of specialist agents (one per attack surface) rather than a single attacker LLM looping over prompts. AgentGuardian runs eleven specialists in parallel under a swarm commander (`src/agent_guardian/core/swarm.py`).

**Agentic-AI focus.** Whether the tool reasons about agent-specific surfaces — tools, memory, A2A traffic, persistence, planning loops — or treats the target as a single-turn chat model.

**Standards aligned.** Which external standard(s) the findings map to. AgentGuardian triple-tags every probe with OWASP ASI + MITRE ATLAS + CSA AICM ([Concepts → Probes — the triple-framework gate](../concepts/probes.md#the-triple-framework-gate)).

**Open formula.** Whether the scoring math is documented and reproducible from open code. AgentGuardian's AIVSS formula is in [Concepts → AIVSS Score](../concepts/aivss.md) and the code is `src/agent_guardian/core/scoring.py`.

**Signed evidence packs.** Whether each scan emits a cryptographically signed artefact a third party can verify without re-running the scan. AgentGuardian signs every JSON report with HMAC-SHA256 plus optional Ed25519 ([Security → Signing & verification](../security/signing.md)).

**0–100 score.** Whether the tool emits a single aggregate severity score suitable for dashboards and gates, vs. per-probe pass/fail only.

## How to read this table

This is a snapshot of public docs as of 2026-05-30 — every cell is hyperlinked in the *Sources* section back to a primary source so you can re-verify. If you spot a row that has drifted, open an issue at <https://github.com/glacien-technologies/agent-guardian/issues> and we will re-run the verification and update the date stamp.

The shape of agentic-security tooling is moving fast. Promptfoo will ship things AgentGuardian doesn't have; AgentGuardian's swarm will pull ahead in places others don't go. Read the table as "what these tools optimise for", not "winners and losers".

## Related reading

- [Concepts → Architecture](../concepts/architecture.md) — how the swarm is wired.
- [Concepts → AIVSS Score](../concepts/aivss.md) — the math behind the 0–100 number.
- [Concepts → Probes](../concepts/probes.md) — the seed corpus and how each probe is tagged.
- [FAQ](../faq/index.md) — the questions that show up before adoption.
- [Roadmap](../reference/roadmap.md) — what is shipping next; honest about what is not.
