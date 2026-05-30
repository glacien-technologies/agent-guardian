*[A2A]: Agent-to-Agent communication. Direct messaging, supervision, or tool-passing between AI agents.
*[AIVSS]: AI Vulnerability Scoring System. The 0–100 deterministic score AgentGuardian emits, aligned with OWASP AIVSS v0.8.
*[ASI]: Agentic Security Initiative. The OWASP working group whose *Top 10 for Agentic Applications 2026* (ASI01–ASI10) AgentGuardian implements.
*[ATLAS]: Adversarial Threat Landscape for Artificial-Intelligence Systems. MITRE's threat-modelling framework for AI/ML systems.
*[Commander]: The orchestrator LLM that decomposes the operator goal into per-agent briefs and re-tasks the swarm.
*[CSA]: Cloud Security Alliance. Publisher of the Agentic AI Red Teaming Guide whose taxonomy AgentGuardian tags every finding against.
*[CSA Agentic-RT]: Cloud Security Alliance Agentic Red Teaming category taxonomy. The third leg of AgentGuardian's triple-framework tagging.
*[DCO]: Developer Certificate of Origin. Sign-off-only contributor agreement (`Signed-off-by:` commit trailer).
*[EgressRefused]: Rules-of-Engagement exception raised when an attacker turn would call a host the contract forbids. Increments `egress_refused_turns` for the report.
*[HMAC-SHA256]: Hash-based Message Authentication Code using SHA-256. Used to sign evidence packs alongside Ed25519.
*[MAD-MAX]: Modular Adversarial Diversity for Maximum-coverage red-teaming. Epsilon-greedy bandit that mixes PAIR / TAP / Crescendo / fuzz / tool-exfil sub-strategies per turn.
*[MCP]: Model Context Protocol. The Anthropic-published standard for agent-tool messaging.
*[MITRE ATLAS]: Adversarial Threat Landscape for Artificial-Intelligence Systems. MITRE's framework AgentGuardian tags every finding against at least one technique ID from.
*[NOT_EVALUATED]: SeverityBand assigned when `scoring_valid=False` — typically because the probe corpus was missing, evaluation_mode is `stub` or `mixed`, or coverage fell below the mode threshold. The numeric AIVSS is retained for debugging only.
*[OWASP-LLM Top 10]: OWASP's 2023–2025 Top 10 for LLM Applications (LLM01–LLM10). Five specialist agents map LLM-class concerns (output handling, fuzzing, secret extraction, denial-of-wallet, detection evasion) onto the nearest ASI category for scoring.
*[OWASP Top 10 for Agentic Applications]: OWASP's 2026 Top 10 for Agentic Applications. The ten ASI01–ASI10 categories AgentGuardian's core swarm targets one-agent-per-category.
*[PAdES-LTA]: PDF Advanced Electronic Signatures, Long-Term Archival. Regulator-grade evidence-pack signing tier — Enterprise-only, not part of OSS.
*[PAIR]: Prompt Automatic Iterative Refinement (Chao et al. 2023). Attacker-LLM iterative critique-and-rewrite strategy.
*[PINNED]: Trust-anchor state in `agent-guardian verify` when the caller supplied `--pubkey` / `--pubkey-file` / `--secret`. The signature was checked against an anchor the caller controls.
*[Probe]: A single YAML attack template — id, ASI / ATLAS / CSA tags, severity, tier floor, seed prompts, expected evidence — validated against `agent_guardian.models.Probe`.
*[ProbeLoader]: `agent_guardian.probes.loader` — walks `src/agent_guardian/probes/asiNN/`, rejects probes missing any of the three framework tags, and exposes `PROBE_CORPUS_VERSION`.
*[Recon agent]: The first specialist in the slate. Maps the target's attack surface (tools, memory, multi-agent, PII) before the ASI attackers start. Writes no findings.
*[ScanMode]: User-facing thoroughness dial. `fast` / `smart` / `full`. `full` is the default since v1.0.
*[SARIF]: Static Analysis Results Interchange Format. OASIS-standard JSON schema AgentGuardian emits at version 2.1.0 for IDE / GitHub Code-Scanning ingestion.
*[Scan]: The Pydantic model `agent_guardian.models.Scan` that wraps a finished run — AIVSS, band, findings, per-ASI scores, mode, evaluation_mode, signatures.
*[Seed]: The static prompt payload at the heart of a probe. The swarm dynamically extends seeds using TAP, Crescendo, MAD-MAX, and PAIR strategies.
*[SSE]: Server-Sent Events. Unidirectional HTTP streaming protocol the dashboard uses to push live scan events to the browser.
*[Swarm]: The set of specialist agents that run concurrently against a target. Default slate: 1 recon + 10 ASI + 5 OWASP-LLM (16 candidate classes, capped at 14 parallel).
*[SwarmCommander]: The Python class in `agent_guardian.core.swarm` that runs recon → decompose → parallel attack → finalise.
*[SwarmConfig]: Frozen dataclass holding the per-run knobs (mode, budgets, model IDs, tier override, `include_m2_agents`).
*[TAP]: Tree of Attacks with Pruning (Mehrotra et al. 2024). Tree-of-thoughts jailbreak strategy with on-topic pruning.
*[Tier]: Target risk tier. T1 Critical (tools + memory + PII), T2 High (tools + memory or multi-agent), T3 Standard (tools or memory), T4 Low (otherwise). Drives the AIVSS per-category weights.
*[Triple-framework tagging]: Every finding carries OWASP ASI + MITRE ATLAS + CSA Agentic-RT category. Enforced by `tests/unit/test_probe_corpus.py::test_triple_framework_tagging`.
*[UNANCHORED]: Trust-anchor state in `agent-guardian verify` when the caller supplied no key material. `verify` exits non-zero to fail closed.
*[evaluation_mode]: One of `real` / `stub` / `mixed`. `stub` means every judge call hit the StubLLM; `mixed` means a real LLM degraded mid-scan to stub. When not `real`, `scoring_valid` is forced False.
*[mode_authoritative]: Boolean in the signed Scan JSON. `True` only when the scan ran in FULL mode *and* `scoring_valid=True`. CI `--fail-under` ignores any scan whose mode is not authoritative.
*[scoring_valid]: Boolean on `Scan` / `AivssResult`. `False` when the corpus was empty, evaluation_mode degraded, or completeness fell below the mode threshold. Forces `band=NOT_EVALUATED`.
*[dashboard ingest token]: Bearer token required by `POST /ingest` on the dashboard. Generated by `agent-guardian serve` and printed at startup; rejects unauthorised pushes from CI.
