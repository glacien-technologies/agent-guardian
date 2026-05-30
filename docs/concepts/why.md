# Why we built this

!!! abstract "TL;DR"
    Single-chain LLM red-teaming tools were built for chatbots. Production agents have tools, memory, A2A channels, and supply chains — a different attack surface that needs a swarm. Read this before the [Architecture](architecture.md) tour to understand the design choice.

## The gap

The first generation of LLM red-teaming tools — PyRIT, garak, Promptfoo, Inspect, DeepTeam — was built for single-chain chatbots. You send a prompt, you get a reply, you grade the reply. That model worked when "the AI" was a text box behind a single model call.

Production agentic systems are not single-chain. They compose multiple tools, hold persistent and shared memory, delegate to other agents, run arbitrary code, and call out to MCP servers and external APIs. The attack surface is no longer "the prompt." It is the entire orchestration graph — the tools, the memory, the agent-to-agent channel, the supply chain, and the human-in-the-loop trust boundary.

OWASP recognised this in 2026 with the **Top 10 for Agentic Applications**: ten new categories (ASI01–ASI10) that have no equivalent in the original LLM Top 10. MITRE released **ATLAS v5.4.0**, the first version with agent-specific tactics. CSA published the **Agentic AI Red Teaming Guide**. Three independent bodies, the same conclusion: agents need a new red team.

A concrete read on the competitor gap as of 2026-05-30:

- **PyRIT** ([microsoft/PyRIT](https://github.com/Azure/PyRIT)) ships orchestrators for single-LLM red-teaming and an "MCP server" mode. Its public docs and `pyrit.orchestrator` API do not model multi-agent memory poisoning, A2A boundaries, or a tier-weighted score that an SRE can gate CI on.
- **garak** ([NVIDIA/garak](https://github.com/NVIDIA/garak)) is a probe-based vulnerability scanner for *generators* — one model, one prompt, one response — explicitly framed as "the nmap for LLMs." Excellent at LLM01 prompt-injection and LLM06 sensitive-info disclosure; not a fit for agentic memory chains or tool misuse.
- **Promptfoo** ([promptfoo/promptfoo](https://github.com/promptfoo/promptfoo)) is an eval / red-team harness. Its red-team mode supports OWASP-LLM-Top-10 plugins; it does not ship an OWASP-Agentic-Top-10 (ASI) probe corpus, an AIVSS-equivalent score, or a shared-memory swarm.

There is no judgement in that list — all three are good tools for the chatbot-era problem they were designed for. The agentic-era problem is different, and the answer is a swarm.

## Why a swarm

A single-chain attacker tests one hypothesis at a time. To find a goal-hijack vulnerability you might need to combine three probes — a memory-injection seed, a tool-misuse follow-up, and a privilege-escalation payload — across two agent boundaries. A serial scanner finds these chains only by exhaustive search, which is intractable.

A **swarm** runs the specialists in parallel against shared memory. Probe A's discovery becomes Probe B's seed. The reconnaissance agent maps the target once, the ten ASI-aligned attackers all read that map, and the Swarm Commander re-tasks idle agents toward whichever surface looks most fruitful. Findings emerge as multi-step chains, not isolated single-prompt hits — because the attackers cooperate the way real adversaries do.

See [The swarm](swarm.md) for the agent slate and the orchestration loop.

## Why an open score

The agentic-security category will standardise on whichever 0–100 score is published openly first. We want that score to be **AIVSS**, the formula the OWASP AIVSS v0.8 working group has been ratifying since late 2025, so production teams have one number they can track over time and one open framework that maps cleanly to OWASP ASI, MITRE ATLAS, and CSA Agentic-RT categories.

AIVSS is deterministic — the scorer is pure Python with no LLM call, no clock read, no randomness; the same evidence pack always produces the same score. It is reproducible — the formula and weights are public in [`src/agent_guardian/core/scoring.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/scoring.py) and walked end-to-end in [AIVSS scoring](aivss.md). And it is signed — every report carries an Ed25519 signature so a 73 yesterday and a 73 today provably refer to the same evidence.

## Why open source

Security tools that ship as opaque SaaS create a market for vendor lock-in on the scoring side. The 0–100 number ends up gated behind a paywall, the methodology is proprietary, and reproducibility dies. We do not want that to be the future of the agentic-security category.

AgentGuardian is Apache-2.0. Telemetry is anonymous and opt-out — disabled by default until the operator runs `agent-guardian telemetry consent`, and even when enabled it ships counters only, no prompts and no findings. See [Telemetry transparency](../security/telemetry.md) for the on-the-wire payload and the opt-out switch. No API-key requirement for the framework. Every probe, every adapter, every weight is in the repo. If you do not trust us, you can read the code. That is the point.

## Academic foundation

The four jailbreak strategies bundled in v1.0 — PAIR, TAP, Crescendo, and MAD-MAX — come straight from the 2024–2025 academic literature on multi-step LLM attacks. The reconnaissance phase implements the tool-graph and memory-graph probing techniques described in the OWASP ASI 2026 reference implementation. We did not invent these; we packaged them into a swarm.

References live in each probe's `references:` field (BibTeX keys) and in the project preprint draft.

--8<-- "_glossary-abbreviations.md"
