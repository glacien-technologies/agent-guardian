# Glossary

- **AIVSS** — AI Vulnerability Scoring System. The 0–100 deterministic score (PRD §6) that AgentGuardian emits, aligned with OWASP AIVSS v0.8.
- **ASI** — Agentic Security Initiative. The OWASP working group whose *Top 10 for Agentic Applications 2026* (ASI01–ASI10) AgentGuardian implements.
- **A2A** — Agent-to-Agent communication. Direct messaging, supervision, or tool-passing between AI agents.
- **Commander** — The Layer-3 orchestrator LLM that re-tasks the swarm based on shared memory. See [Architecture](architecture.md).
- **DCO** — Developer Certificate of Origin. Sign-off-only contributor agreement (`Signed-off-by:` commit trailer); a permissive alternative to a corporate CLA.
- **HMAC-SHA256** — Hash-based Message Authentication Code using SHA-256. Used to sign evidence packs alongside Ed25519.
- **MCP** — Model Context Protocol. The Anthropic-published standard for agent-tool messaging.
- **MITRE ATLAS** — Adversarial Threat Landscape for Artificial-Intelligence Systems. MITRE's threat-modelling framework for AI/ML systems; AgentGuardian tags every finding with at least one ATLAS technique ID.
- **PAdES-LTA** — PDF Advanced Electronic Signatures, Long-Term Archival. The regulator-grade evidence-pack signing tier; **Enterprise-only**, not part of the OSS package.
- **PAIR** — Prompt Automatic Iterative Refinement (Chao et al. 2023). Attacker-LLM iterative critique-and-rewrite strategy.
- **Probe** — A single seed test case, declared as YAML and validated against `agent_guardian.models.Probe`. The OSS package ships **92** probes in `src/agent_guardian/probes/` (corpus version `2026.05`, exposed as `agent_guardian.PROBE_CORPUS_VERSION`).
- **Recon agent** — The Layer-1 specialist that maps a target's attack surface before the 10 ASI attackers start.
- **Seed** — The static prompt payload at the heart of a probe. The swarm dynamically extends seeds using TAP, Crescendo, MAD-MAX, and PAIR strategies.
- **SSE** — Server-Sent Events. The unidirectional HTTP streaming protocol the dashboard uses to push live scan events to the browser.
- **Swarm** — The set of 11 specialist agents (1 recon + 10 ASI-aligned attackers) that run concurrently against a target.
- **TAP** — Tree of Attacks with Pruning (Mehrotra et al. 2024). Tree-of-thoughts jailbreak strategy with on-topic pruning.
- **Tier** — Target risk tier. T1 Critical (tools + memory + PII), T2 High, T3 Standard, T4 Low. Tier shapes the AIVSS weighting per PRD §6.4.
- **Triple-framework tagging** — Every finding carries OWASP ASI + MITRE ATLAS + CSA Agentic-RT category. Enforced by `tests/unit/test_probe_corpus.py::test_triple_framework_tagging`.
