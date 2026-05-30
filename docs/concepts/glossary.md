# Glossary

!!! abstract "TL;DR"
    Canonical definitions for the terms used across the AgentGuardian docs. Hover any abbreviated term elsewhere on the site to see the short form; come here for the long form. Source of truth for the tooltip snippet at [`docs/_glossary-abbreviations.md`](https://github.com/glacien-technologies/agent-guardian/blob/main/docs/_glossary-abbreviations.md).

## Core concepts

**AgentGuardian** — The Apache-2.0 Python package and CLI in this repository. One word, no "Open" suffix. The product name is set in [`mkdocs.yml`](https://github.com/glacien-technologies/agent-guardian/blob/main/mkdocs.yml) and [`pyproject.toml`](https://github.com/glacien-technologies/agent-guardian/blob/main/pyproject.toml).

**AIVSS** — AI Vulnerability Scoring System. The 0–100 deterministic score AgentGuardian emits, aligned with OWASP AIVSS v0.8. The formula version is locked in `agent_guardian.AIVSS_FORMULA_VERSION` (`"aivss-v1"`, see [`src/agent_guardian/core/scoring.py:45`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/scoring.py#L45)). See [AIVSS scoring](aivss.md).

**ASI** — Agentic Security Initiative. The OWASP working group whose *Top 10 for Agentic Applications 2026* (ASI01–ASI10) AgentGuardian implements one-agent-per-category.

**A2A** — Agent-to-Agent communication. Direct messaging, supervision, or tool-passing between AI agents. Owned by the `a2a-agent` (ASI07).

**Commander** — The orchestrator LLM (OpenAI / Anthropic / Bedrock / Vertex / stub) that decomposes the operator goal into per-agent briefs and re-tasks the swarm. Implemented in `SwarmCommander._phase_decompose_with_llm` ([`src/agent_guardian/core/swarm.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py)).

**MAD-MAX** — Modular Adversarial Diversity for Maximum-coverage red-teaming (Schoepf et al. 2025). Epsilon-greedy bandit that mixes PAIR / TAP / Crescendo / fuzz / tool-exfil sub-strategies per turn. Implemented at [`src/agent_guardian/strategies/mad_max.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/strategies/mad_max.py).

**PAIR** — Prompt Automatic Iterative Refinement (Chao et al. 2023). Attacker-LLM iterative critique-and-rewrite strategy. Implemented at [`src/agent_guardian/strategies/pair.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/strategies/pair.py).

**Probe** — A single YAML attack template. Required fields: `id`, `asi`, `mitre_atlas`, `csa_category`, `severity`, `tier_floor`, `seeds`, `description`, `expected_evidence`, `remediation_ref`, `references`. Validated against `agent_guardian.models.Probe`. The OSS package ships corpus version `2026.05`, exposed as `agent_guardian.PROBE_CORPUS_VERSION` ([`src/agent_guardian/probes/loader.py:34`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/probes/loader.py#L34)). See [Probes](probes.md).

**ProbeLoader** — The loader at `agent_guardian.probes.loader`. Walks `src/agent_guardian/probes/asiNN/`, rejects probes missing any of the three framework tags, and sets `last_load_was_authoritative()` so a missing-corpus scan downgrades to `NOT_EVALUATED` rather than silently returning 100/100.

**Recon agent** — The first specialist in the slate. Maps the target's attack surface (tools, memory, multi-agent, PII) before the ASI attackers start. Writes no findings — only a `TargetFingerprint`. Implemented at [`src/agent_guardian/agents/recon.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/recon.py).

**ScanMode** — User-facing thoroughness dial. `fast` / `smart` / `full`. `full` is the default since v1.0 (commit `91c73c4`, 2026-05-28). See [Scan modes](scan-modes.md). Defined at [`agent_guardian.core.swarm.ScanMode`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py).

**Seed** — The static prompt payload at the heart of a probe. The swarm dynamically extends seeds using TAP, Crescendo, MAD-MAX, and PAIR strategies.

**Swarm** — The set of specialist agents that run concurrently against a target. Default slate: 1 recon + 10 ASI-aligned + 5 OWASP-LLM specialists (16 candidate classes, capped at 14 running in parallel; [`src/agent_guardian/cli.py:2376`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L2376)). Pass `--no-owasp-llm` for the 11-agent ASI-only slate (cap drops to 10). See [The swarm](swarm.md).

**SwarmCommander** — The Python class in [`agent_guardian.core.swarm`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py) that runs recon → decompose → parallel attack → finalise.

**SwarmConfig** — Frozen dataclass holding the per-run knobs (mode, budgets, model IDs, tier override, `include_m2_agents`).

**TAP** — Tree of Attacks with Pruning (Mehrotra et al. 2024). Tree-of-thoughts jailbreak strategy with on-topic pruning. Implemented at [`src/agent_guardian/strategies/tap.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/strategies/tap.py).

**Tier** — Target risk tier. T1 Critical (tools + memory + PII), T2 High (tools + (memory or multi-agent)), T3 Standard (tools or memory), T4 Low (otherwise). Drives the AIVSS per-category weights. Detection logic at [`src/agent_guardian/core/tiering.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/tiering.py). See [Target tiers](tiers.md).

## Standards & frameworks

**MITRE ATLAS** — Adversarial Threat Landscape for Artificial-Intelligence Systems. MITRE's threat-modelling framework for AI/ML systems; AgentGuardian tags every finding with at least one ATLAS technique ID.

**OWASP-LLM Top 10** — OWASP's 2023–2025 Top 10 for *LLM Applications* (LLM01–LLM10). Five specialist agents map LLM-class concerns onto the nearest ASI category for scoring: `output-handling-agent` → ASI09 for LLM02, `fuzzing-agent` → ASI02 for LLM05, `secret-extraction-agent` → ASI01 for LLM07, `denial-of-wallet-agent` → ASI08 for LLM10, and `detection-evasion-agent` → ASI10 for coverage. See [`src/agent_guardian/agents/__init__.py:39`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/agents/__init__.py#L39).

**OWASP Top 10 for Agentic Applications** — OWASP's 2026 *Top 10 for Agentic Applications*. The ten ASI01–ASI10 categories AgentGuardian's core swarm targets one-agent-per-category.

**Triple-framework tagging** — Every finding carries OWASP ASI + MITRE ATLAS + CSA Agentic-RT category. Enforced by [`tests/unit/test_probe_corpus.py::test_triple_framework_tagging`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/test_probe_corpus.py) and by `ProbeLoader` itself, which rejects probes missing any of the three tags. See [Threat coverage](threat-coverage.md).

**CSA Agentic-RT** — Cloud Security Alliance Agentic Red Teaming category taxonomy. The third leg of the triple-framework tagging.

## Reports, signatures, transports

**HMAC-SHA256** — Hash-based Message Authentication Code using SHA-256. Symmetric-secret signature on the evidence pack, useful when both signer and verifier share a secret.

**PAdES-LTA** — PDF Advanced Electronic Signatures, Long-Term Archival. Regulator-grade evidence-pack signing tier — **Enterprise-only**, not part of OSS.

**SARIF** — Static Analysis Results Interchange Format. OASIS-standard JSON schema. AgentGuardian emits SARIF 2.1.0 via [`src/agent_guardian/reports/sarif.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/reports/sarif.py), validated against the bundled `sarif-2.1.0.schema.json` by [`tests/unit/reports/test_sarif_contract.py`](https://github.com/glacien-technologies/agent-guardian/blob/main/tests/unit/reports/test_sarif_contract.py).

**Scan** — The Pydantic model `agent_guardian.models.Scan` that wraps a finished run — AIVSS, band, findings, per-ASI scores, mode, evaluation_mode, signatures.

**PINNED** — Trust-anchor state in `agent-guardian verify` when the caller supplied `--pubkey` / `--pubkey-file` / `--secret`. The signature was checked against an anchor the caller controls. Surfaced as `trust anchor: PINNED` in CLI output ([`src/agent_guardian/cli.py:1304`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/cli.py#L1304)).

**UNANCHORED** — Trust-anchor state when the caller supplied no key material. `verify` exits non-zero to fail closed.

## Runtime, modes, and contracts

**evaluation_mode** — One of `real` / `stub` / `mixed`. `stub` means every judge call hit the in-process StubLLM; `mixed` means a real LLM degraded mid-scan to stub. When not `real`, `scoring_valid` is forced False ([`src/agent_guardian/core/swarm.py:1531`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L1531)).

**scoring_valid** — Boolean on `Scan` / `AivssResult`. `False` when the corpus was empty, evaluation_mode degraded, or completeness fell below the mode threshold. Forces `band=NOT_EVALUATED` ([`src/agent_guardian/core/swarm.py:1981`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L1981)).

**NOT_EVALUATED** — `SeverityBand` value assigned when `scoring_valid=False`. The numeric AIVSS is kept for debugging but should not be quoted. See [AIVSS scoring](aivss.md#not_evaluated-semantics).

**mode_authoritative** — Boolean in the signed `Scan` JSON. `True` only when the scan ran in FULL mode *and* `scoring_valid=True`. CI `--fail-under` ignores any scan whose mode is not authoritative ([`src/agent_guardian/core/swarm.py:2054`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/swarm.py#L2054)).

**EgressRefused** — Rules-of-Engagement exception raised when an attacker turn would call a host the contract forbids. Defined at [`src/agent_guardian/core/roe.py:165`](https://github.com/glacien-technologies/agent-guardian/blob/main/src/agent_guardian/core/roe.py#L165); increments `egress_refused_turns` so the report can prove the refusals were counted, not silently lost.

**dashboard ingest token** — Bearer token required by `POST /ingest` on the dashboard. Generated by `agent-guardian serve` and printed at startup; rejects unauthorised pushes from CI.

## Process

**DCO** — Developer Certificate of Origin. Sign-off-only contributor agreement (`Signed-off-by:` commit trailer); a permissive alternative to a corporate CLA.

**MCP** — Model Context Protocol. The Anthropic-published standard for agent-tool messaging. AgentGuardian probes the MCP tool surface via the `tool-abuse-agent` (ASI02).

**SSE** — Server-Sent Events. Unidirectional HTTP streaming protocol the dashboard uses to push live scan events to the browser.

--8<-- "_glossary-abbreviations.md"
