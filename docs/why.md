# Why we built this

## The gap

The first generation of LLM red-teaming tools — PyRIT, garak, Promptfoo,
Inspect, DeepTeam — was built for single-chain chatbots. You send a prompt,
you get a reply, you grade the reply. That model worked when "the AI" was a
text box behind a single model call.

Production agentic systems are not single-chain. They compose multiple
tools, hold persistent and shared memory, delegate to other agents, run
arbitrary code, and call out to MCP servers and external APIs. The attack
surface is no longer "the prompt." It is the entire orchestration graph —
the tools, the memory, the agent-to-agent channel, the supply chain, and
the human-in-the-loop trust boundary.

OWASP recognised this in 2026 with the **Top 10 for Agentic Applications**:
ten new categories (ASI01–ASI10) that have no equivalent in the original
LLM Top 10. MITRE released **ATLAS v5.4.0**, the first version with
agent-specific tactics. CSA published the **Agentic AI Red Teaming Guide**.
Three independent bodies, the same conclusion: agents need a new red team.

## Why a swarm

A single-chain attacker tests one hypothesis at a time. To find a
goal-hijack vulnerability you might need to combine three probes — a
memory-injection seed, a tool-misuse follow-up, and a privilege-escalation
payload — across two agent boundaries. A serial scanner finds these chains
only by exhaustive search, which is intractable.

A **swarm** runs the specialists in parallel against shared memory. Probe
A's discovery becomes Probe B's seed. The reconnaissance agent maps the
target once, the ten ASI-aligned attackers all read that map, and the
Swarm Commander re-tasks idle agents toward whichever surface looks most
fruitful. Findings emerge as multi-step chains, not isolated single-prompt
hits — because the attackers cooperate the way real adversaries do.

## Why an open score

The agentic-security category will standardise on whichever 0–100 score is
published openly first. We want that score to be **AIVSS**, the formula
the OWASP AIVSS v0.8 working group has been ratifying since late 2025, so
production teams have one number they can track over time and one open
framework that maps cleanly to OWASP ASI, MITRE ATLAS, and CSA Agentic-RT
categories.

AIVSS is deterministic — the same evidence pack always produces the same
score. It is reproducible — the formula and weights are public, in
[`docs/aivss-formula.md`](aivss-formula.md). And it is signed — every
report carries an Ed25519 signature so a 73 yesterday and a 73 today
provably refer to the same evidence.

## Why open source

Security tools that ship as opaque SaaS create a market for vendor lock-in
on the scoring side. The 0–100 number ends up gated behind a paywall, the
methodology is proprietary, and reproducibility dies. We do not want that
to be the future of the agentic-security category.

AgentGuardian Open is Apache-2.0, with no telemetry, no API-key
requirement, and a published formula. Every probe, every adapter, every
weight is in the repo. If you do not trust us, you can read the code.
That is the point.

## Academic foundation

The four jailbreak strategies bundled in v1.0 — PAIR, TAP, Crescendo, and
MAD-MAX — come straight from the 2024–2025 academic literature on
multi-step LLM attacks. The reconnaissance phase implements the
tool-graph and memory-graph probing techniques described in the OWASP ASI
2026 reference implementation. We did not invent these; we packaged them
into a swarm.

## What we want from you

Use it. Find bugs. Submit probes. Build adapters for the frameworks we
have not covered. File CVE-style disclosures responsibly via the
[security policy](https://github.com/glacien-technologies/agent-guardian/blob/main/SECURITY.md).
The agentic-security category is being defined right now, in 2026, and
the more eyes on the framework the better the number gets.
